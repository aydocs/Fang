package distributed

import (
	"sync"
	"time"

	"github.com/aydocs/fang/pkg/models"
)

type NodeType string

const (
	NodeController NodeType = "controller"
	NodeWorker     NodeType = "worker"
)

type Node struct {
	ID       string
	Type     NodeType
	Address  string
	Status   string
	Capacity int
	Load     int
	LastSeen time.Time
}

type Task struct {
	ID         string
	ScanID     string
	TargetURL  string
	Modules    []string
	Status     string
	AssignedTo string
	CreatedAt  time.Time
}

type Cluster struct {
	nodes    map[string]*Node
	tasks    map[string]*Task
	mu       sync.RWMutex
	nodeType NodeType
	rrIndex  int
}

func NewCluster(nodeType NodeType) *Cluster {
	return &Cluster{
		nodes:    make(map[string]*Node),
		tasks:    make(map[string]*Task),
		nodeType: nodeType,
	}
}

func (c *Cluster) RegisterNode(n *Node) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n.LastSeen = time.Now()
	c.nodes[n.ID] = n
}

func (c *Cluster) RemoveNode(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.nodes, id)
}

func (c *Cluster) ListNodes() []*Node {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]*Node, 0, len(c.nodes))
	for _, n := range c.nodes {
		out = append(out, n)
	}
	return out
}

func (c *Cluster) DispatchTask(task *Task) string {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.tasks[task.ID] = task
	task.Status = "pending"
	task.CreatedAt = time.Now()

	var workers []*Node
	for _, n := range c.nodes {
		if n.Type == NodeWorker && n.Status == "available" && n.Load < n.Capacity {
			workers = append(workers, n)
		}
	}

	if len(workers) == 0 {
		task.Status = "queued"
		return task.ID
	}

	idx := c.rrIndex % len(workers)
	c.rrIndex++
	worker := workers[idx]
	task.AssignedTo = worker.ID
	task.Status = "assigned"
	worker.Load++
	return task.ID
}

func (c *Cluster) GetTask(id string) *Task {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.tasks[id]
}

func (c *Cluster) StoreTask(t *Task) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tasks[t.ID] = t
}

func (c *Cluster) UpdateTaskStatus(id, status string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.tasks[id]; ok {
		t.Status = status
	}
}

func (c *Cluster) CompleteTask(id string, findings []*models.Finding) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.tasks[id]; ok {
		t.Status = "completed"
		if t.AssignedTo != "" {
			if n, ok := c.nodes[t.AssignedTo]; ok {
				n.Load--
				if n.Load < 0 {
					n.Load = 0
				}
			}
		}
	}
}
