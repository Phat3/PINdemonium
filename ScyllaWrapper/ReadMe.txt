========================================================================
    LIBRERIA A COLLEGAMENTO DINAMICO: cenni preliminari sul progetto 
    ScyllaWrapper
========================================================================

La creazione guidata applicazione ha creato questa DLL 
ScyllaWrapper.

Questo file contiene un riepilogo del contenuto di ciascun file che fa parte
dell'applicazione ScyllaWrapper.


ScyllaWrapper.vcxproj
    File di progetto principale per i progetti VC++ generati tramite una 
    creazione guidata applicazione.
    Contiene informazioni sulla versione di Visual C++ che ha generato il file e
    informazioni sulle piattaforme, le configurazioni e le caratteristiche del 
    progetto selezionate con la Creazione guidata applicazione.

ScyllaWrapper.vcxproj.filters
    File dei filtri per i progetti VC++ generati tramite una Creazione guidata 
    applicazione. 
    Contiene informazioni sull'associazione tra i file del progetto e i filtri. 
    Tale associazione viene utilizzata nell'IDE per la visualizzazione di
    raggruppamenti di file con estensioni simili in un nodo specifico, ad 
    esempio: i file con estensione cpp sono associati al filtro "File di 
    origine".

ScyllaWrapper.cpp
    File di origine della DLL principale.

    Una volta creata, questa DLL non esporta alcun simbolo. Di conseguenza, non
    produrrà un file LIB quando viene compilata. Se si desidera impostare 
    questo progetto come dipendenza di un altro progetto, sarà necessario
    aggiungere il codice per esportare alcuni simboli dalla DLL in modo da 
    produrre una libreria di esportazione oppure impostare la proprietà Ignore 
    Input Library su Yes nella pagina delle proprietà Generale della cartella 
    Linker nella finestra di dialogo Pagine delle proprietà del progetto.

/////////////////////////////////////////////////////////////////////////////
Altri file standard:

StdAfx.h, StdAfx.cpp
    Tali file vengono utilizzati per compilare un file di intestazione
    precompilato denominato ScyllaWrapper.pch e un file dei tipi 
    precompilato denominato StdAfx.obj.

/////////////////////////////////////////////////////////////////////////////
Altre note:

La creazione guidata applicazione utilizza i commenti "TODO:" per indicare le
parti del codice sorgente da aggiungere o personalizzare.

/////////////////////////////////////////////////////////////////////////////
