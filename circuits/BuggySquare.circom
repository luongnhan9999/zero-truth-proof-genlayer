pragma circom 2.1.6;

template BuggySquare() {
    signal input x;
    signal output out;
    out <-- x * x;
}

component main = BuggySquare();
