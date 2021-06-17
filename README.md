## What is OpenMUL ?

Open Mul is an Openflow / SDN controller platform. It has a C language 
based multi-threaded infrastructure at its core. It supports a multi-level 
north bound interface for hosting applications. It aims to support various 
SDN enabling south-bound protocols such as Openflow 1.4, 1.3 and 1.0 along 
with ovsdb, of-config etc.

It is designed for performance and reliability which is the need of the hour 
for deployment in mission-critical networks. It is also highly flexible, 
modular and easy to learn.

## How to get openmul source-code ?

$  git clone https://github.com/openmul/openmul.git

For getting source code based on permissive license (eg Apache or BSD) or any support, please contact support@openmul.org

## How to build MUL Controller on Ubuntu/CentOS ?

1. Run all-in-one build command : 

 a) For Ubuntu 12.04 LTS/CentOS-5 or higher, run the following command : 
   
   $ ./build.sh 

   The above command will install all necessary packages and build necessary modules.

 b) For using the GUI, follow the INSTALL.GUI readme file

2. Executables will be built as :

   Core :  <top-mul-dir>/mul/mul
   Application (eg l2switch) :  <top-mul-dir>/application/l2switch/mull2sw
                   
   - Other applications will be built in their respective directories inside <top-mul-dir>/application/
   - You need to run using sudo or as admin.

6. How to run ?
    
    Mul provides an utility startup script for various use cases :  
     
    1. Initialize MuL's execution environment
    2. Start MuL and its components

    $ cd <top-mul-dir>
    $ ./mul.sh start l2switch   ## Run in l2switch mode
    
    OR,

    $ ./mul.sh start fabric     ## Run in fabric 

    OR,

    $ ./mul.sh -h               ## Show all options

7. Please follow openmul documentation in <top-mul-dir>/docs  

8. For further information please visit www.openmul.org
