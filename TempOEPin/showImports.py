import idaapi
import idc
tmpDirectory = "C:\Users\phate\Desktop\pin\TempOEPin"
outputFile = tmpDirectory + "\detectedInitFunc.txt"
inputFile =  tmpDirectory + "\initFuncList.txt"
initFunc = []

outputF = open(outputFile,"w") 

def imp_cb(ea, name, ord):
  
  for func in initFunc:
    if not name:
      print "%08x: ord#%d" % (ea, ord)
      return True #go to next function
    if name == func:
      print "Found at %08x %s (ord#%d)" % (ea, func, ord)
      outputF.write(hex(ea)+","+func+","+str(ord)+"\n")
  return True

def loadInitFunc():
  with open(inputFile) as f:
    for line in f:
      initFunc.append(line.rstrip())
  print "Loaded functions %s" % initFunc 


def main():
  loadInitFunc()
  nimps = idaapi.get_import_module_qty()

  print "Found %d import(s)..." % nimps

  for i in xrange(0, nimps):
    name = idaapi.get_import_module_name(i)
    if not name:
      print "Failed to get import module name for #%d" % i
      continue
    idaapi.enum_import_names(i, imp_cb)

  print "All done..."
  outputF.close()

idaapi.autoWait()
main()
idc.Exit(0)

