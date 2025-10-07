#!/bin/bash

# Start a new tmux session named "pres"
tmux new-session -d -s pres

# Create a new window for editors
tmux new-window -t pres:0 -n "presentation"

# Split the editor window into panes
tmux split-window -v -t pres:0
tmux split-window -h -t pres:0
tmux split-window -v -t pres:0

# Send commands to each pane
tmux send-keys -t pres:0.0 "make dbg && make setuid && make run" C-m
tmux send-keys -t pres:0.1 "watch -n0.1 tree ./jail/content/" C-m
tmux send-keys -t pres:0.2 "watch -n0.1 cat ./jail/content/files/A" C-m
tmux send-keys -t pres:0.3 "watch -n0.1 'stat --printf "\""Created: %w\nLast accessed: %x\nLast modified: %y\nLast changed: %z\n"\"" ./jail/content/files/A'" C-m

# Select window 0 and attach to the session
tmux select-window -t pres:0
tmux attach-session -t pres
