package main

// knownUnread is the backlog: operator-settable configuration fields nothing in
// the product reads, each with the verdict from reading the code around it.
//
// This is a shrinking list, not a suppression list. A finding absent from here
// fails the run, and an entry that no longer reproduces fails it too, so an
// entry leaves only when the field gains a reader or the field goes.
//
// EMPTY IS THE ANSWER, and it is the answer because the destination for a field
// with no reader is not this register. It is internal/common/config/retired.go:
// delete the field, the default and the binding, and add the environment
// variable to retiredSettings so that an operator who still sets it is told at
// startup that it does nothing and what to set instead. A register entry leaves
// the operator's belief intact and only records that we know better.
//
// So an entry here means one thing: a field that cannot be retired yet because
// something outside this repository still depends on the name. There is nothing
// in that position today.
var knownUnread = map[string]string{}
