Antemir Andreea-Catalina 324CA

## Dataplane Router - Tema 1 PCOM

### Forwarding
- presupune validarea si actualizarea header elor inaintr de a le trimite mai
departe
- calculam checksum ul header ului ip, iar daca acesta difera de valoarea
primita in pachet inseamna ca pachetul este corupt deci ii dam drop
- daca nu am dat drop la pachet, verificam ttl ul
- acesta trebuie sa fie > 1, iar daca aceasta conditie nu este indeplinita dam
drop la pachet intrucat acesta a expirat
- daca conditia a fost indeplinita, decrementam ttl ul si recalculam checksum ul
header ului ip intrucat am schimbat ttl ul
- modificam adresele mac din antetul ethernet si tremitem pachetul mai departe

### LPM
- pentru o performanta ridicata, am modificat algoritmul clasic liniar de lpm
- am sortat elementele din tabela de rutare folosind radix sort stabil
crescator in functie de masca si apoi crescator in functie de prefix,
astfel avand o complexitate O(n)
- dupa ce aam terminat sortarea, cautam cea mai buna ruta folosind cautarea
binara, avand o complexitate O(logn)
- daca am gasit un match, verificam si intrarile adiacente din tabela, pentru a
ne asigura ca nu ratam un match mai bun (o masca mai lunga)

### ARP
- routerul mentine un cache cu adresele mac deja aflate pentru a minimiza traficul
inutil
- cand routerul trebuie sa trimita un pachet dar nu gaseste adresa mac a destinatiei
in cache, pachetul este salvat temporar intr o coada, trimitand imediat un mesaj
de arp request pentru a afla cui ii este desinat pachetul
- dupa ce primeste inapoi un arp replay, routerul actualizeaza cache ul si extrage
din coada toate pachetele care erau destinate adresei mac si le trimite

### ICMP
- in momentul cand routerul renunta la pachete, comunica starea retelei prin
mesaje icmp
- daca routerul primeste un pachet icmp de tip echo request care are ca destinatie
adresa uneia dintre interfetele sale, nu face forwarding, ci trimite inapoi
expeditorului un pachet echo reply
- daca procesul de lpm esueaza, adica nu gaseste nicio ruta valida si returneaza
NULL, routerul trimite inapoi un pachet icmp destination unreachable
- daca ttl ul pachetului ajunge <= 1 inante de a ajunge la destinatie, routerul
trimite inapoi un pachet icmp time exceeded
