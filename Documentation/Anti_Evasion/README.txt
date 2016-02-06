Per compilare la tesi e' necessario avere il sistema latex installato ed eseguire la seguente sequenza di comandi:

latex tesi
bibtex tesi
latex tesi
latex tesi
dvips -Ppdf -G0 -ta4 tesi.dvi
ps2pdf14 -sPAPERSIZE=a4 tesi.ps tesi.pdf

oppure usare lo script compilatex.sh:

./compilatex.sh tesi

oppure usare (dopo aver sistemato le immagini pero') pdflatex

pdflatex tesi.tex
bibtex tesi
pdflatex tesi.tex
pdflatex tesi.tex

Buon lavoro!
