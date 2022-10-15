## Requirements
Upgrade `pip` to the latest version

	pip install --upgrade pip
    
Install project dependencies

    pip install -r requirements.txt

Run

    ./mulnbapi

 a) run REST server with https protocol
    configure nbapi REST server to handle https requests
    (follow mul-top-dir/utils/nbapi-ssl-cert/README)
    
    ./mulnbapi https

 b) run nbapi REST server as daemon

    ./mulnbapi -d

 c)configure nbapi REST server port(default 8181)

    ./mulnbapi --port=[port_num] [arg]
