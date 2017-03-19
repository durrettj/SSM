#!/bin/sh
#
# (c) 2017 J. Edward Durrett - jed@jedwarddurrett.com - https://jedwarddurrett.com
#

alert_log="/var/log/snort/alert"
snort_logdir="/var/log/snort"

show_alerts() {
    awk '/^\[\*/' $alert_log | cut -d' ' -f 2- | sed -e 's/\[\*\*\]//' | sort -n | uniq -c | sort -r  
}

alert_by_src() {
    awk '/^[0-9]/' $alert_log | awk '/[\->]/' | awk '{print$2}' | cut -d ":" -f1 > tmp.tmp
    awk '/^[0-9]/' $alert_log | awk '/[<\-]/' | awk '{print$4}' | cut -d ":" -f1 >> tmp.tmp
    cat tmp.tmp |sort -n | uniq -c | sort -r | head -10
    rm tmp.tmp
}

alert_by_dst() {
    awk '/^[0-9]/' $alert_log | awk '/[<\-]/' | awk '{print$4}' | cut -d ":" -f1 > tmp.tmp
    awk '/^[0-9]/' $alert_log | awk '/[\->]/' | awk '{print$2}' | cut -d ":" -f1 >> tmp.tmp
    cat tmp.tmp |sort -n | uniq -c | sort -r | head -10
    rm tmp.tmp
}

alert_by_src_port() {
    awk '/^[0-9]/' $alert_log | awk '/[\->]/' | awk '{print$2}' | cut -d ":" -f2 > tmp.tmp
    awk '/^[0-9]/' $alert_log | awk '/[<\-]/' | awk '{print$4}' | cut -d ":" -f2 >> tmp.tmp
    cat tmp.tmp |sort -n | uniq -c | sort -r | head -10
    rm tmp.tmp
}

alert_by_dst_port() {
    awk '/^[0-9]/' $alert_log | awk '/[\->]/' | awk '{print$4}' | cut -d ":" -f2 > tmp.tmp
    awk '/^[0-9]/' $alert_log | awk '/[<\-]/' | awk '{print$2}' | cut -d ":" -f2 >> tmp.tmp
    cat tmp.tmp |sort -n | uniq -c | sort -r | head -10
    rm tmp.tmp
}

get_detail() {
    cat $alert_log | grep $cmd
}

get_packets() {
    pcapfile=`ls -lh $snort_logdir/| grep "snort.log" | awk '{print$9}' | sort -n| tail -1`
    cat $alert_log | grep -A6 $id | grep -e "^[0-9][0-9][/][0-9][0-9]" | cut -d "-" -f2 | \ 
    awk '{print$1}' | while read timestamp; do 
        echo $id
        echo $pcapfile
        echo $timestamp
        tcpdump -XX -n -r $snort_logdir/$pcapfile | grep -A50 $timestamp  
    done
}

alert_stat_menu() {
    printf "\nOptions:\nStats by (d)estination ip\nStats by source (i)p \nStats by (s)ource port\n"
    printf "Stats by destination (p)ort\nReturn to (a)lerts\nEnter option:"
    read stats
}

get_network_assets () {
    nmap -O -Pn -T5 -oG net_map.txt $network
}

case $1 in 
    alerts)
        while true; do
            clear
            printf "\nSnort Alert Summary:\n\n"
            show_alerts
            printf "\nOptions: alert (d)etail | show (s)tats | (q)uit:"
            read -t 100 cmd
            case $cmd in
                s|S)
                    while true; do
                        clear
                        printf "\n\nTop IPs triggering alerts by source:\n"
                        alert_by_src
                        alert_stat_menu
                        case $stats in
                            d|D)
                                clear
                                printf "\n\nTop IPs triggering alerts by destination:\n"
                                alert_by_dst
                                alert_stat_menu
                                ;;
                            i|I)
                                clear
                                printf "\n\nTop IPs triggering alerts by source:\n"
                                alert_by_src
                                alert_stat_menu
                                ;;
                            s|S)
                                clear
                                printf "\n\nTop source ports:\n"
                                alert_by_src_port
                                alert_stat_menu
                                ;;
                            p|P)
                                clear
                                printf "\n\nTop destination ports:\n"
                                alert_by_dst_port
                                alert_stat_menu
                                ;;    
                            a|A)
                                break    
                                ;;    
                        esac
                    done
                    ;; 
                q|Q)
                    exit 1
                    ;;
                d)
                    printf "\n\nEnter Snort ID you want to see more about or (q)uit:" 
                    read id
                    case $id in
                        q|Q)
                            exit 1
                            ;;
                        [0-9]*)
                            cat $alert_log | grep -A5 $id
                            printf "\n\nSee full (p)acket or (r)eturn or (q)uit:"    
                            read pd
                            case $pd in
                                p)
                                    get_packets
                                    printf "\nEnter to continue." 
                                    read enter
                                    ;;
                                r)
                                    ;;
                                q)
                                    exit 1
                                    ;;
                            esac        
                            ;;
                        *)
                            printf "\n\nError: enter alert id" 
                            ;;    
                    esac                
            esac    
        done
esac

