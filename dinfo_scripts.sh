#! /bin/bash

#Version 1.0

domain=$1

redirection=$(curl --connect-timeout 2 --max-time 4 -Ls -o /dev/null -w %{url_effective} $domain)
ip_address=$(dig +short -t A $domain)
dnssec_record=$(dig +short ds $domain)
ptr_record=$(dig -x $ip_address +short)

webserver=$(echo "$ptr_record" | sed 's/-[0-9]*\././')

if [ -z "$webserver" ]; then
    webserver="Missing"
    server_type="Unknown"
else
    server_type=$(curl -sLI "$webserver" | grep -i 'Server:' | awk '{print $2}')

    if [ -z "$server_type" ]; then
        server_type="Unknown"
    fi
fi

light_blue="\e[1;34m"  
reset_color="\e[0m"    

output_webserver="$webserver -- $server_type"

mx_records=$(dig $domain -t MX +short | sort -n -k1,1 | tr '\n' '|' | sed 's/|$//')
spf_record=$(dig -t TXT $domain +short | grep 'v=spf1')

if [ -z "$spf_record" ]; then
    spf_record="Missing"
fi

if [ -z "$ptr_record" ]; then
    ptr_record=$(echo -e "\e[0;31mmissing\e[0m")
fi

dkim_record=$(dig -t TXT default._domainkey.$domain +short)
if [ -z "$dkim_record" ]; then
    dkim_record="Missing"
fi

if [ -z "$dnssec_record" ]; then
    dnssec_record=$(echo -e "\e[0;32mdisabled\e[0m")
else
    dnssec_record=$(echo -e "$dnssec_record \e[0;31m=> enabled\e[0m")
fi

dmarc_record=$(dig -t TXT _dmarc.$domain +short)
if [ -z "$dmarc_record" ]; then
    dmarc_record=$(echo -e "\e[0;31mmissing\e[0m")
fi

if echo "$redirection" | grep -q 'http'; then
    if echo "$redirection" | grep -q 'https'; then
        protocol="https"
        port="443"
    else
        protocol="http"
        port="80"
    fi
else
    protocol="https"
    port="443"
fi

ttfb=$(curl -o /dev/null -sw "%{time_starttransfer}\n" "$protocol://$domain" --resolve "$domain:$port:$ip_address")

redirection=$(echo "$redirection" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
ttfb=$(echo "$ttfb" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
ip_address=$(echo "$ip_address" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
mx_records=$(echo "$mx_records" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

echo "------------------------------"
printf "%-20s : %s\n" "Redirection" "$redirection"
printf "%-20s : %s\n" "TTBF value" "$ttfb"
printf "%-20s : %s\n" "IP address" "$ip_address"
printf "%-20s : %s\n" "PTR Record" "$ptr_record"
printf "%-20s : %s\n" "DNSSEC" "$dnssec_record"
printf "%-20s : %s\n" "Webserver" "$output_webserver"
printf "%-20s : %s\n" "MX Records" "$mx_records"
printf "%-20s : %s\n" "SPF Record" "$spf_record"
printf "%-20s : %s\n" "DKIM Record" "$dkim_record"
printf "%-20s : %s\n" "DMARC Record" "$dmarc_record"

whois $domain | grep -E "Registrar:|Updated Date:|Registry Expiry Date:|Registrar URL:|Name Server:" | while IFS= read -r line
do
    key=$(echo "$line" | cut -d: -f1 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    value=$(echo "$line" | cut -d: -f2- | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    printf "%-20s : %s\n" "$key" "$value"
done
echo "------------------------------"
