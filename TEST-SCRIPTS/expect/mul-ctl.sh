#!/usr/bin/expect -f

set length [llength $argv]
incr length -1
set args [lrange $argv 3 $length]

set adddel [lindex $argv 1]
set kind [lindex $argv 0]
set dpid [lindex $argv 2]
set senddata ""

set sendcommand ""
set check 1
if { $kind != "flow" && $kind != "meter" && $kind != "group"} {
    set check -1
    puts "first argument $kind should be flow, meter or group"
}
if { $adddel != "add" && $adddel != "del"} {
    set check -1
    puts "second argument $adddel should be add or del"
}

if { [regexp "^\[a-z]+$" $dpid] == 1 } {
    set check -1
    puts "third argument $dpid cannot be dpid"
}

if { $check == -1 } {
    puts "\r\rUSAGE : <flow|meter|group> <add|del> <dpid> <data....>\r"
    exit 1
}

set senddata "of-$kind $adddel switch $dpid"

proc merge { command data } {
    set buffer ""
    set i 0
    while { [llength $command] > $i } {
        set buffer "$buffer [lindex $command $i] [lindex $data $i]"
        incr i 1
    }
    return $buffer
}




proc itsflow { } {
    global args
    set flowcommand "smac dmac eth-type vid vlan-pcp mpls-label mpls-tc mpls-bos dip sip proto tos dport sport in-port table"
    set flowdata "* * * * * * * * * * * * * * * 0"
    foreach command $flowcommand {
    set i -1
    set i [lsearch $args $command]
    if { $i != -1 } {
        incr i 1
        set data [lindex $args $i]
        set i [lsearch $flowcommand $command]
        set flowdata [lreplace $flowdata $i $i $data]
        if { ($command == "vid") || ($command == "vlan-pcp") || ($command == "dip") || ($command == "sip") || ($command == "proto") || ($command == "tos") || ($command == "dport") || ($command == "sport") } {
        set i [lsearch $flowcommand "eth-type"]
        set flowdata [lreplace $flowdata $i $i "0x0800"]
        }
        if { ($command == "mpls-label") || ($command == "mpls-tc") || ($command == "mpls-bos") } {
        set i [lsearch $flowcommand "eth-type"]
        set flowdata [lreplace $flowdata $i $i "0x8847"]
        }
        if { $command == "vlan-pcp" } {
        set i [lsearch $flowcommand "vid"]
        set vid [lindex $flowdata $i]
        if { $vid == "*" } {
            set flowdata [lreplace $flowdata $i $i "0"]
        }
        }

    }
}
    return [merge $flowcommand $flowdata]
}

proc itsmeter { } {
    global args
    set metercommand "meter-id meter-type burst stats"
    set meterdata "0 kbps yes no"
    
    foreach command $metercommand {
        set i -1
        set i [lsearch $args $command]
        if { $i != -1 } {
            incr i 1
            set data [lindex $args $i]
            set i [lsearch $metercommand $command]
            set meterdata [lreplace $meterdata $i $i $data]
        }
    }
    return [merge $metercommand $meterdata]
}

proc itsgroup { } {
    global args
    set groupcommand "group type"
    set groupdata "0 all"
    foreach command $groupcommand {
        set i -1
        set i [lsearch $args $command]
        if { $i != -1 } {
            incr i 1
            set data [lindex $args $i]
            set i [lsearch $groupcommand $command]
            set groupdata [lreplace $groupdata $i $i $data]
        }
    }
    return [merge $groupcommand $groupdata]
}

proc instflow { } {
global args
set instructioncommand1 "instruction-apply instruction-write flow-stats-enable flow-barrier-enable"
set instructioncommand2 "instruction-meter instruction-goto"
set instructions ""
set result ""

set actioncommand1 "cp-ttl-in cp-ttl-out dec-mpls-ttl dec-nw-ttl drop push-mpls-header push-pbb-header push-svlan-header push-vlan-header strip-pbb-header strip-vlan"
set actioncommand2 "group-id nw-daddr nw-saddr output set-dmac set-eth-type set-mpls-label set-mpls-tc set-mpls-ttl set-queue set-smac set-vlan-id set-vlan-pcp strip-mpls-header"

foreach data $args {
    set i [lsearch "$instructioncommand1 $instructioncommand2" $data]
    if { $i != -1 } {
        set instructions "$instructions $data"
    }

    foreach command $instructions {
    set result "$result $command /"
    set start [lsearch $args $command]
    incr start 1
    set end [llength $args]
if { [lsearch $instructions $command] < [llength $instructions] -1 } {
    set nextindex [lsearch $instructions $command]
    incr nextindex 1
    set next [lindex $instructions $nextindex]
    set end [lsearch $args $next]
}
    incr end -1
    for { set i $start} { $i <= $end } { incr i 1} {
        foreach action $actioncommand1 {
            if { $action == [lindex $args $i] } {
                set result "$result action-add $action /"  
            }
        }
        foreach action $actioncommand2 {
    
       if { $action == [lindex $args $i] } {
                set result "$result action-add $action"
                incr i 1
                set result "$result [lindex $args $i] /"
            }
        }
    }
        set result "$result action-list-end /"
    }
}
    return "$result commit /"
}
proc instmeter { } {
    global args
    set command1 "meter-band drop rate * burst-size *"
    set command2 "meter-band dscp-remark rate * burst-size * prec-level *"
    set result ""
    set i 0
    set max 0

    while { [lsearch $args "meter-band"] != -1} {
        set i [lsearch $args "meter-band"]
        set j $i+5
        set word1 [lrange $args $i $j]
        set j $i+7
        set word2 [lrange $args $i $j]
        if { [string match $command1 $word1] == 1} {
            set result "$result $word1 /"
            incr max 1
        } elseif { [string match $command2 $word2] == 1 } {
            set result "$result $word2 /"
            incr max 1
        } else {
            puts "USAGE : \r
                 meter-band drop rate <1-65535> burst-size <1-65535>\r
                 meter-band dscp-remark rate <1-65535> burst-size <1-65535> prec-level <0-7>\r"
            exit 1
        }
        set args [lreplace $args $i $i ""]
        if { [lsearch $args "meter-band"] != -1} {
            set result "$result meter-band-next /"
        }
    }
    if { $max >= 64 } {
        puts "USAGE : Too many meter-band"
    }
    
    set result "$result commit-meter /"
    return $result
}

proc instgroup { } {
    global args
    set result ""
    set groupactvector "ff-group ff-port weight"
    set groupcommand "group-act-vector-next group-state-enable"
    set groupaction1 "cp-ttl-in cp-ttl-out dec-mpls-ttl dec-nw-ttl drop push-mpls-header push-pbb-header push-svlan-header push-vlan-header strip-pbb-header strip-vlan"
    set groupaction2 "nw-daddr nw-saddr output set-dmac set-eth-type set-mpls-bos set-mpls-tc set-mpls-ttl set-mw-ttl set-queue set-smac set-vlan-id set-vlan-pcp strip-mpls-header"

    for { set i 0 } { $i < [llength $args] } { incr i 1} {
        set arg [lindex $args $i]
        if { [lsearch $groupactvector $arg] != -1 } {
            set result "$result group-act-vector [lrange $args $i $i+1] /"
            incr i 1
        }
        if { [lsearch $groupcommand $arg] != -1 } {
            set result "$result $arg /"
        }
        if { [lsearch $groupaction1 $arg] != -1 } {
            set result "$result action-add $arg /"
        }
        if { [lsearch $groupaction2 $arg] != -1 } {
            set result "$result action-add [lrange $args $i $i+1] /"
            incr i 1
        }
        if { [lindex $args $i] == "group-act-vector" } {
            incr i 1
            set check [lsearch $groupactvector [lindex $args $i]]
            if { $check != -1 } {
                set result "$result group-act-vector [lrange $args $i $i+1] /"
                incr i 1
            }
        }
    }
    return "$result commit-group /"
}

switch -- $kind {
    "flow" {
        set senddata "$senddata[itsflow]"
        set sendcommand "[instflow]"
    }
    "meter" {
        set senddata "$senddata[itsmeter]"
        set sendcommand "[instmeter]"
    }
    "group" {
        set senddata "$senddata[itsgroup]"
        set sendcommand "[instgroup]"
    }
}
#puts $senddata
#puts "$sendcommand"


spawn telnet localhost 10000
expect ">"
send "enable\r"
expect "#"
send "conf term\r"
expect "#"
#send "do show of-switch all\r"
#expect "#"
send "mul-conf\r"
expect "#"
if { $adddel == "del" } {
    if { ($kind == "meter") || ($kind == "group") } {
        set senddata [lrange $senddata 0 5]
    }
}
send "$senddata\r"
expect "#"
if { $adddel == "add"} {
set command ""
for { set i 0 } { $i < [llength $sendcommand] } { incr i 1 } {
    if { [lindex $sendcommand $i] == "/" } {
        set command "$command\r"
        send $command
        expect "#"
        set command ""
    } else {
        set command "$command [lindex $sendcommand $i]"
    }
}
}
send "exit\r"
expect "#"
send "exit\r"
expect "#"
send "exit\r"
expect eof


