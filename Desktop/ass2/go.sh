./make.sh
sudo ./attack
kill $(ps aux | grep 'go.sh' | awk '{print $2}')
