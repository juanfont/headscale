package types

type Change struct {
	NodeChange NodeChange
	UserChange UserChange
}

type NodeChangeWhat string

const (
	NodeChangeCameOnline NodeChangeWhat = "node-online"
)

type NodeChange struct {
	ID   NodeID
	What NodeChangeWhat
}

type UserChange struct {
	ID UserID
}
