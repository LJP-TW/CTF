$$
n = dq \\
a^{d-1} \equiv 1 \mod d \\
a^{k(d-1)} \equiv 1 \mod d \\
a^{k(d-1)(q-1)} \equiv 1 \mod d \\
a^{k(d-1)(q-1)} \equiv 1 \mod q \\
a^{k(d-1)(q-1)} \equiv 1 \mod n \\
a^{k(d-1)(q-1)+1} \equiv a \mod n \\
ed \equiv 1 \mod (d-1)(q-1) \\
ed = 1 + k(d-1)(q-1) \\
$$

$$
c^d \equiv m \mod dq \\
c^{d-1} \equiv 1 \mod d \\
c^d \equiv c \mod d \\
c^{ed} \equiv c^{e} \mod d \\
c^{e(d-1)} \equiv c^{ed-e} \equiv 1^e \equiv 1 \mod d \\
c^{ed-e} = kd + 1\\
c^{ed} = c^ekd + c^e\\
c^{ed} \equiv c \equiv c^e + c^ekd \mod n \\
0 \equiv c^e + c^ekd - c \mod n \\
0 \equiv 1 + kd - c^{1-e} \mod n \\
c^{1-e} - 1 \equiv kd \mod n \\
$$

$$
ed = 1 + kdq - kd - kq + k \\
a^{ed} \equiv a^{1 + kdq - kd - kq + k} \equiv a \mod (d-1)(q-1) \\
a^{ed-1} \equiv a^{kdq - kd - kq + k} \equiv 1 \mod (d-1)(q-1) \\
$$

