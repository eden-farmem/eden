count=0
errors=0
while : ; do
    sudo /home/ayelam/rmem-scheduler/shenango//iokerneld 0000:d8:00.1 2>&1 &> iok.out &
    PID=$!
    echo process: $PID
    sleep 5
    if ps -p $PID > /dev/null
    then
        echo "$PID is running"
    else 
        echo "$PID is not running"
        errors=$((errors+1))
        cat iok.out
    fi 
    count=$((count+1))
    if [[ $count -eq 10 ]]; then 
        break
    fi
    sudo pkill iokerneld
    sleep 5
done
echo $count, $errors
