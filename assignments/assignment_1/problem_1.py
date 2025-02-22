# Python version 3.9 or later

import os
import timeit
import matplotlib.pyplot as plt
import numpy as np

# This is a helper function that returns the length of the input N in bytes.
#
# The cryptographically secure randomness generator, os.urandom, takes as input an
# integer 'size' and outputs 'size' random bytes. These bytes can be interpretted as an
# integer between 0 and 256**size - 1 (both inclusive).
#
# To sample a random number between 0 and N, we compute 'size' so that 256**size is the
# smallest power of 256 greater than or equal to N.
def num_rand_bytes(N):
    return (N.bit_length() + 7) // 8


# Alice's random number generator
def alice_rand_gen(N):
    num_bytes = num_rand_bytes(N)

    # Initialize with a sentinel so that at least one iteration of the loop is run.
    val = N + 1
    iteration_count = 1
    # Keep re-sampling until we obtain a value less that or equal to N.
    while val > N:
        # Get securely generated random bytes.
        random_bytes = os.urandom(num_bytes)
        # Convert the bytestring returned by os.urandom to an integer.
        val = int.from_bytes(random_bytes, "big")
        iteration_count = iteration_count + 1

    return val, iteration_count

# Bob's random number generator
def bob_rand_gen(N):
    num_bytes = num_rand_bytes(N)

    # Get securely generated random bytes.
    random_bytes = os.urandom(num_bytes)

    # Convert the bytestring returned by os.urandom to an integer and reduce it modulo
    # (N+1) to obtain a value between 0 and N.
    val = int.from_bytes(random_bytes, "big") % (N + 1)

    return val


# print(timeit.timeit("alice_rand_gen(103)", setup="from __main__ import alice_rand_gen", number=200))
# print(timeit.timeit("bob_rand_gen(103)", setup="from __main__ import bob_rand_gen", number=200))

x = []
y = []
N = 103
for i in range(1000000):
    val1, _ = alice_rand_gen(N)
    val2  = bob_rand_gen(N)
    x.append(val1)   
    y.append(val2)
     
numbers_generated = list(range(104))
# print(numbers_generated)

frequency_x = np.zeros(104, dtype=int)
unique_x, counts_x = np.unique(x, return_counts=True)
frequency_x[unique_x] = counts_x

frequency_y = np.zeros(104, dtype=int)
unique_y, counts_y = np.unique(y, return_counts=True)
frequency_y[unique_y] = counts_y

plt.figure()
plt.bar(np.arange(104), frequency_x, color='lightblue', edgecolor='black')
plt.xlabel("Number generated from  Alice's function")
plt.ylabel("Frequency")
plt.xticks(ticks=np.arange(0, 104, 5), rotation=90)

plt.figure()
plt.bar(np.arange(104), frequency_y, color='lightgreen', edgecolor='black')
plt.xlabel("Number generated from Bob's function")
plt.ylabel("Frequen`cy")
plt.xticks(ticks=np.arange(0, 104, 5), rotation=90)

plt.show()

# Problem 1.3 - Expected number of iterations in the loop of Alice's function when N = 256. Running for 300000 iterations
total_iteration_count = 0
for i in range(300000):
    _, iteration_count = alice_rand_gen(256)
    total_iteration_count += iteration_count
expectation = total_iteration_count/300000
print(f"Expected number of iterations : {expectation}")

""" Tried a more mathematical approach to find the expected number of iterations -- didn't work. I'll leave it here for now, will come back to it later.
probability_x = frequency_x/len(x)
probability_y = frequency_y/len(y)

expectation_x = [iteration_count_x*probability_x for iteration_count_x,probability_x in zip(iteration_count_x,probability_x)]
expectation_y = [iteration_count_y*probability_y for iteration_count_y,probability_y in zip(iteration_count_y,probability_y)]

# print(sum(expectation_x))
# print(sum(expectation_y))
"""



