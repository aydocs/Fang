package distributed

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/aydocs/fang/pkg/models"
)

func TestTransportHeartbeatRegistersNode(t *testing.T) {
	cluster := NewCluster(NodeController)
	srv := NewServer(cluster)
	if err := srv.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer srv.Close()

	workerCluster := NewCluster(NodeWorker)
	self := Node{ID: "worker-1", Type: NodeWorker, Address: "127.0.0.1:0", Status: "available", Capacity: 4}
	cli := NewClient(workerCluster, self)
	if err := cli.Connect(srv.Addr().String()); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer cli.Close()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		found := false
		for _, n := range cluster.ListNodes() {
			if n.ID == "worker-1" {
				found = true
			}
		}
		if found {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("worker node was not registered via heartbeat")
}

func TestTransportTaskResultCompletesTask(t *testing.T) {
	cluster := NewCluster(NodeController)
	task := &Task{ID: "t1", Status: "assigned", AssignedTo: "worker-1"}
	cluster.StoreTask(task)

	srv := NewServer(cluster)
	if err := srv.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer srv.Close()

	self := Node{ID: "worker-1", Type: NodeWorker, Status: "available", Capacity: 4}
	cli := NewClient(cluster, self)
	if err := cli.Connect(srv.Addr().String()); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer cli.Close()

	res := TaskResult{TaskID: "t1", Findings: []*models.Finding{{Title: "x", Severity: models.High}}}
	payload, _ := json.Marshal(res)
	if err := cli.Send(Message{Type: MsgTaskResult, From: "worker-1", Payload: payload}); err != nil {
		t.Fatalf("send: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cluster.GetTask("t1").Status == "completed" {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("task was not completed via task_result message")
}
