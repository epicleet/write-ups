#!/bin/python3


def pair(n):
    return n & 1 == 1


if __name__ == "__main__":
    with open('crypt') as fp:
        lst = list(map(int, fp.read().strip().split()))[::-1]

    while True:
        while lst[-1] == 0:
            lst = lst[:-1]
        if len(lst) % 2 == 1:
            lst.append(0)
        ndiff, idiff = 0, -1
        for i in range(0, len(lst), 2):
            if pair(lst[i]) != pair(lst[i+1]):
                ndiff += 1
                idiff = i+1
        if ndiff > 1:
            break
        lst[idiff] ^= 1
        for i in range(0, len(lst), 2):
            lst[i], lst[i+1] = (lst[i]+lst[i+1])//2, (lst[i]-lst[i+1])//2

    while lst[-1] == 0:
        lst = lst[:-1]

    with open('FLAG', 'wb') as fp:
        fp.write(bytes(lst))