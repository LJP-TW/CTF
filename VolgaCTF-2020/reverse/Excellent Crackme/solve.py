import pandas as pd
import numpy as np

# 44 x 46
my_data = np.genfromtxt('array.csv', delimiter=',', dtype='i8')

print(my_data)
print(my_data.shape)

a = my_data[:,0:45]
b = my_data[:, 45]

print('--------------')
print(a)
print('--------------')
print(b)
print('--------------')

x = np.linalg.solve(a, b)
print(x)
print('--------------')

r = ''
for i in x:
    r += chr(int(round(i)))
print(r)

