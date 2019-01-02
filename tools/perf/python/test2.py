#! /usr/bin/python3

import perfsample

def krava1(i):
    for i in range(i):
        pass
    pass

def krava2(i):
    for i in range(i):
        pass
    krava1(i)
    pass

def krava3(i):
    for i in range(i):
        pass
    krava2(i)
    pass

while True:
    krava1(1000)
    krava2(2000)
    krava3(4000)
