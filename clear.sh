#!/bin/bash

# Usuwanie polaczen i namespace'ow
for namespace in red green blue yellow
do
ip link del vt-${namespace} 2> /dev/null
ip link del vt-${namespace}-br
ip netns del ns-${namespace}
done

# Usuwanie mostka
ip link del br-host type bridge
