package distributed

import (
	"encoding/json"
	"time"
)

type MessageType string

const (
	MsgHeartbeat  MessageType = "heartbeat"
	MsgTaskAssign MessageType = "task_assign"
	MsgTaskResult MessageType = "task_result"
	MsgNodeStatus MessageType = "node_status"
)

type Message struct {
	Type      MessageType
	From      string
	To        string
	Payload   json.RawMessage
	Timestamp time.Time
}
