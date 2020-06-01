with open('exam1.txt', 'r') as f:
    line = f.readlines();

counter = [0 for i in range(65537)]

for i in range(len(line)):
    port = int(line[i].split()[3].split(':')[1])
    counter[port] += 1
    print('{}: {}, counter[{}]: {}'.format(i, port, port, counter[port]))

biggest = [counter.index(x) for x in sorted(counter, reverse=True)[:3]]

print(biggest)
    
# flag{0e2c3e4dd79f9a26e591728c8af4e8347403127a}