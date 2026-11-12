import serial, sys, time
port, label = sys.argv[1], sys.argv[2]
out = f"{label}_{int(time.time())}.csv"
s = serial.Serial(port, 115200, timeout=1)
with open(out, "w") as f:
    f.write("t_ms,seq,auth_ok,len,rssi,iat_ms,current,temp,hum,press,pir,label\n")
    while True:
        line = s.readline().decode(errors="ignore").strip()
        if line and line[0].isdigit() and line.count(",") == 10:
            f.write(line + "," + label + "\n")
            f.flush()
