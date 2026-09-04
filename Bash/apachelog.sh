
#!/bin/bash

LOG_FILE="/var/log/apache2/access.log"

if [ ! -f "$LOG_FILE" ]
then
    echo "$LOG_FILE not found!"
    exit 1
fi
awk '{
    split($7,method," ")
    count[method[1]" "$1]++
}
END {
    for (i in count)
        print i, count[i]
}' $LOG_FILE
             