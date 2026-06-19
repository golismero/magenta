#!/usr/bin/env python3

# Use this script to add new client simulation name mappings when they are updated in testssl.sh.
# We keep ALL of them for backwards compatibility reasons.

import pickle

with open("clients.pickle", "rb") as fd:
    clients = pickle.load(fd)

with open("client-simulation.txt", "r") as fd:
    for line in fd:
        line = line.strip()
        if line.startswith("names+="):
            value = line[9:-2]
        elif line.startswith("short+="):
            key = line[9:-2]
            if key not in clients:
                print("New: %s: %r" % (key, value))
                clients[key] = value
            elif clients[key] != value:
                print("Updated: %s: %r -> %r" % (key, clients[key], value))

with open("clients.pickle", "wb") as fd:
    pickle.dump(clients, fd, protocol=0)
