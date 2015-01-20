for i in {1..255}
do
for j in {1..255}
do
sudo ip route add $i.$j.110.0/24 via 11.11.11.3 dev s1-peth1
done
done
