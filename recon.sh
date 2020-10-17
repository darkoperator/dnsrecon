#!/bin/bash

domain=$1
wordlist=https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS --Download and add path here..
ressolvers="add txt file of all ip that u want to resolve"

domain_enum(){

mkdir -p $domain $domain/sources $domain/Recon/ 
#Passive Enumeration
subdinder -d domain=$1 -o $domain/sources/subfinder.txt
assestfinder -subs-only domain=$1 | tee $domain/sources/hackerone.txt
amass enum -passive domain=$1 -o $domain/sources/passive.txt

#Active Enumeration using brutefoorce
shuffledns -d $domain -w $wordlist -r $resolvers -o $domain/sources/suffledns.txt

cat $domain/sources/*.txt > $domain/sources/all.txt

}
domain_enum


resolving_domains(){

suffledns -d $domain  -list $domain/sources/all.txt -o $domain/domain.txt -r $ressolvers


}
resolving_domains


http_prob(){
cat $domain/domain.txt | httpx -thread 50 -o $domain/Recon/httpx.txt
}
http_prob









