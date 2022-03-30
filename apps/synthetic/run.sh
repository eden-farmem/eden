
for N in 10000 1000000; do
    for ALPHA in 0.1 0.5 1 10; do
        python zipf.py $N $ALPHA $((N*10)) > zipf_${N}_$ALPHA
    done
done