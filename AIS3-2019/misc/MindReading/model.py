#!/usr/bin/env python3

# pylint: disable=import-error
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import Embedding, Dense, Flatten

import numpy as np
import random

chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}'

def encode(string):
    '''Encode string into indeces according to chars.'''
    return np.array([chars.index(c) for c in string])

def decode(indeces):
    '''Decode indeces of chars into string.'''
    return ''.join(map(chars.__getitem__, indeces))

def build_model(flag_size, dim):
    '''Build a model to classify flag and non-flags.'''
    model = Sequential()
    model.add(Embedding(dim, 32, input_length=flag_size))
    model.add(Flatten())
    model.add(Dense(512, activation='relu'))
    model.add(Dense(256, activation='relu'))
    model.add(Dense(128, activation='relu'))
    model.add(Dense(1, activation='sigmoid'))

    model.compile(
        loss='binary_crossentropy',
        optimizer='adam',
        metrics=['accuracy'])

    return model

def generate_noise(size, dim):
    '''Generate random indeces within range(dim).'''
    return np.random.randint(dim, size=size)

def dataset(dataset_size, flag, dim):
    '''Construct dataset for training.'''
    m_true = dataset_size // 2
    m_false = dataset_size - m_true

    x_true = np.tile(flag, (m_true, 1))
    y_true = np.ones((m_true, 1))

    x_false = np.stack(generate_noise(flag.size, dim) for _ in range(m_false))
    y_false = np.zeros((m_false, 1))

    idxs = list(range(dataset_size))
    random.shuffle(idxs)

    xs = np.concatenate((x_true, x_false), axis=0)[idxs]
    ys = np.concatenate((y_true, y_false), axis=0)[idxs]

    return xs, ys


if __name__ == '__main__':

    with open('flag.txt') as f:
        flag = encode(f.read().strip())

    model = build_model(flag.size, len(chars))
    model.summary()

    for i in range(16):
        model.fit(
            *dataset(4096, flag, len(chars)),
            batch_size=32, epochs=1, verbose=True)

    model.save('model.h5')


    def flag_score(x):
        return model.predict(x.reshape(1, -1))[0][0]

    print(decode(flag), flag_score(flag))

    for _ in range(10):
        noise = generate_noise(flag.size, len(chars))
        print(decode(noise), flag_score(noise))
