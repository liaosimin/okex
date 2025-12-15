package ws

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/amir-the-h/okex"
	"github.com/amir-the-h/okex/events"
	"github.com/gorilla/websocket"
)

// ClientWs is the websocket api client
//
// https://www.okex.com/docs-v5/en/#websocket-api
type ClientWs struct {
	DoneChan            chan interface{}
	StructuredEventChan chan interface{}
	RawEventChan        chan *events.Basic
	ErrChan             chan *events.Error
	SubscribeChan       chan *events.Subscribe
	UnsubscribeCh       chan *events.Unsubscribe
	LoginChan           chan *events.Login
	SuccessChan         chan *events.Success
	url                 map[bool]okex.BaseURL
	sendMu              sync.Mutex
	privateConn         *websocket.Conn
	publicConn          *websocket.Conn
	dialer              *websocket.Dialer
	apiKey              string
	secretKey           []byte
	passphrase          string
	Private             *Private
	Public              *Public
	Trade               *Trade
	ctx                 context.Context
	Logger              *log.Logger
}

const ()

// NewClient returns a pointer to a fresh ClientWs
func NewClient(ctx context.Context, apiKey, secretKey, passphrase string, url map[bool]okex.BaseURL) (*ClientWs, error) {
	c := &ClientWs{
		apiKey:     apiKey,
		secretKey:  []byte(secretKey),
		passphrase: passphrase,
		ctx:        ctx,
		url:        url,
		DoneChan:   make(chan interface{}),
		dialer:     websocket.DefaultDialer,
		Logger:     log.New(os.Stdout, "", log.LstdFlags|log.Lshortfile),
	}
	c.Private = NewPrivate(c)
	c.Public = NewPublic(c)
	c.Trade = NewTrade(c)
	if err := c.Connect(true); err != nil {
		return nil, err
	}
	if err := c.Connect(false); err != nil {
		return nil, err
	}
	if err := c.Login(); err != nil {
		c.Logger.Println("login error:", err)
		return nil, err
	}
	return c, nil
}

func (c *ClientWs) getConn(p bool) *websocket.Conn {
	if p {
		return c.privateConn
	}
	return c.publicConn
}

func (c *ClientWs) setConn(p bool, conn *websocket.Conn) {
	if p {
		c.privateConn = conn
	} else {
		c.publicConn = conn
	}
}

// Connect into the server
//
// https://www.okex.com/docs-v5/en/#websocket-api-connect
func (c *ClientWs) Connect(p bool) error {
	if c.getConn(p) != nil {
		return nil
	}
	conn, res, err := c.dialer.Dial(string(c.url[p]), nil)
	if err != nil {
		var statusCode int
		if res != nil {
			statusCode = res.StatusCode
		}
		fmt.Printf("dail url:%s err:%v res:%+v \n", c.url[p], err, res)
		return fmt.Errorf("dail url:%s err:%v statusCode:%d", c.url[p], err, statusCode)
	}
	c.setConn(p, conn)

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Printf("error closing body: %v\n", err)
		}
	}(res.Body)

	go c.receiver(p)
	go c.keepAlive(p)

	return nil
}

// Login
//
// https://www.okex.com/docs-v5/en/#websocket-api-login
func (c *ClientWs) Login() error {
	method := http.MethodGet
	path := "/users/self/verify"
	ts, sign := c.sign(method, path)
	args := []map[string]string{
		{
			"apiKey":     c.apiKey,
			"passphrase": c.passphrase,
			"timestamp":  ts,
			"sign":       sign,
		},
	}
	return c.Send(true, okex.LoginOperation, args)
}

// Subscribe
// Users can choose to subscribe to one or more channels, and the total length of multiple channels cannot exceed 4096 bytes.
//
// https://www.okex.com/docs-v5/en/#websocket-api-subscribe
func (c *ClientWs) Subscribe(p bool, ch []okex.ChannelName, args ...map[string]string) error {
	chCount := max(len(ch), 1)
	tmpArgs := make([]map[string]string, chCount*len(args))

	n := 0
	for i := 0; i < chCount; i++ {
		for _, arg := range args {
			tmpArgs[n] = make(map[string]string)
			for k, v := range arg {
				tmpArgs[n][k] = v
			}
			if len(ch) > 0 {
				tmpArgs[n]["channel"] = string(ch[i])
			}
			n++
		}
	}

	return c.Send(p, okex.SubscribeOperation, tmpArgs)
}

// Unsubscribe into channel(s)
//
// https://www.okex.com/docs-v5/en/#websocket-api-unsubscribe
func (c *ClientWs) Unsubscribe(p bool, ch []okex.ChannelName, args map[string]string) error {
	tmpArgs := make([]map[string]string, len(ch))
	for i, name := range ch {
		tmpArgs[i] = make(map[string]string)
		tmpArgs[i]["channel"] = string(name)
		for k, v := range args {
			tmpArgs[i][k] = v
		}
	}
	return c.Send(p, okex.UnsubscribeOperation, tmpArgs)
}

// Send message through either connections
func (c *ClientWs) Send(p bool, op okex.Operation, args []map[string]string, extras ...map[string]string) error {
	data := map[string]interface{}{
		"op":   op,
		"args": args,
	}
	for _, extra := range extras {
		for k, v := range extra {
			data[k] = v
		}
	}
	j, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return c.send(p, j)
}

func (c *ClientWs) send(p bool, data []byte) error {
	conn := c.getConn(p)
	if conn == nil {
		return fmt.Errorf("connection is nil")
	}
	if err := conn.SetWriteDeadline(time.Now().Add(time.Second * 3)); err != nil {
		c.Logger.Println("[okx] keepAlive SetWriteDeadline error:", err)
		return err
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
		c.Logger.Println("[okx] keepAlive WriteMessage error:", err)
		return err
	}
	return nil
}

// SetChannels to receive certain events on separate channel
func (c *ClientWs) SetChannels(errCh chan *events.Error, subCh chan *events.Subscribe, unSub chan *events.Unsubscribe, lCh chan *events.Login, sCh chan *events.Success) {
	c.ErrChan = errCh
	c.SubscribeChan = subCh
	c.UnsubscribeCh = unSub
	c.LoginChan = lCh
	c.SuccessChan = sCh
}

// SetDialer sets a custom dialer for the WebSocket connection.
func (c *ClientWs) SetDialer(dialer *websocket.Dialer) {
	c.dialer = dialer
}

func (c *ClientWs) SetEventChannels(structuredEventCh chan interface{}, rawEventCh chan *events.Basic) {
	c.StructuredEventChan = structuredEventCh
	c.RawEventChan = rawEventCh
}

func (c *ClientWs) keepAlive(p bool) {
	ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := c.send(p, []byte("ping")); err != nil {
				c.Logger.Println("[okx] send ping error:", err)
				if err := c.reconnect(p); err != nil {
					c.Logger.Println("[okx] reconnect error:", err)
					continue
				}
			}
		case <-c.ctx.Done():
			_ = c.handleCancel("keepAlive")
		}
	}
}

func (c *ClientWs) receiver(p bool) {
	for {
		select {
		case <-c.ctx.Done():
			_ = c.handleCancel("receiver")
		default:
			conn := c.getConn(p)
			if conn == nil {
				c.Logger.Println("[okx] receiver error: connection is nil")
				time.Sleep(time.Second * 1)
				continue
			}
			mt, data, err := conn.ReadMessage()
			if err != nil {
				c.Logger.Println("[okx] receiver error:", err)
				if err := c.reconnect(p); err != nil {
					c.Logger.Println("[okx] reconnect error:", err)
					time.Sleep(time.Second * 5)
					continue
				}
			}
			if mt == websocket.TextMessage && string(data) != "pong" {
				e := &events.Basic{}
				if err := json.Unmarshal(data, &e); err != nil {
					c.Logger.Println("[okx] receiver json.Unmarshal error:", err)
					continue
				}
				go func() {
					c.process(data, e)
				}()
			}
		}
	}
}

func (c *ClientWs) reconnect(p bool) error {

	conn := c.getConn(p)
	if conn != nil {
		err := conn.Close()
		if err != nil {
			c.Logger.Println("[okx] close conn error:", err)
		}
	}

	var err2 error
	for retry := 0; retry < 3; retry++ {
		newConn, _, err := c.dialer.Dial(string(c.url[p]), nil)
		if err != nil {
			c.Logger.Printf("[okx] reconnect err:%v, %d", err, retry)
			time.Sleep(time.Millisecond * (time.Duration(retry) * 500))
			continue
		}
		err2 = err
		c.setConn(p, newConn)
		if err := c.Login(); err != nil {
			c.Logger.Println("[okx] login error:", err)
		}
		return nil
	}
	c.Logger.Printf("[okx] reconnect err:%v, give up", err2)
	return err2
}

func (c *ClientWs) sign(method, path string) (string, string) {
	t := time.Now().UTC().Unix()
	ts := fmt.Sprint(t)
	s := ts + method + path
	p := []byte(s)
	h := hmac.New(sha256.New, c.secretKey)
	h.Write(p)
	return ts, base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func (c *ClientWs) handleCancel(msg string) error {
	go func() {
		c.DoneChan <- msg
	}()
	return fmt.Errorf("operation cancelled: %s", msg)
}

func (c *ClientWs) process(data []byte, e *events.Basic) bool {
	switch e.Event {
	case "error":
		e := events.Error{}
		_ = json.Unmarshal(data, &e)
		if c.ErrChan != nil {
			c.ErrChan <- &e
		}
		return true
	case "subscribe":
		e := events.Subscribe{}
		_ = json.Unmarshal(data, &e)
		if c.SubscribeChan != nil {
			c.SubscribeChan <- &e
		}
		if c.StructuredEventChan != nil {
			c.StructuredEventChan <- e
		}
		return true
	case "unsubscribe":
		e := events.Unsubscribe{}
		_ = json.Unmarshal(data, &e)
		if c.UnsubscribeCh != nil {
			c.UnsubscribeCh <- &e
		}
		if c.StructuredEventChan != nil {
			c.StructuredEventChan <- e
		}
		return true
	case "login":
		e := events.Login{}
		_ = json.Unmarshal(data, &e)
		if c.LoginChan != nil {
			c.LoginChan <- &e
		}
		if c.StructuredEventChan != nil {
			c.StructuredEventChan <- e
		}
		return true
	}
	if c.Private.Process(data, e) {
		return true
	}
	if c.Public.Process(data, e) {
		return true
	}
	if e.ID != "" {
		if e.Code != 0 {
			ee := *e
			ee.Event = "error"
			return c.process(data, &ee)
		}
		e := events.Success{}
		_ = json.Unmarshal(data, &e)
		if c.SuccessChan != nil {
			c.SuccessChan <- &e
		}
		if c.StructuredEventChan != nil {
			c.StructuredEventChan <- e
		}
		return true
	}
	c.RawEventChan <- e
	return false
}
