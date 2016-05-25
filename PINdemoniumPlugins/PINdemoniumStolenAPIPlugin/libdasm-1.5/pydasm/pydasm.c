
/*
 * pydasm -- Python module wrapping libdasm
 * (c) 2005 ero / dkbza.org
 *
*/


#include <Python.h>
#include "../libdasm.h"


#define INSTRUCTION_STR_BUFFER_LENGTH   256

/*
    Instruction types borrowed from
    "libdasm.h"
*/
char *instruction_types[] = {
	"INSTRUCTION_TYPE_ASC",
	"INSTRUCTION_TYPE_DCL",
	"INSTRUCTION_TYPE_MOV",
	"INSTRUCTION_TYPE_MOVSR",
	"INSTRUCTION_TYPE_ADD",
	"INSTRUCTION_TYPE_XADD",
	"INSTRUCTION_TYPE_ADC",
	"INSTRUCTION_TYPE_SUB",
	"INSTRUCTION_TYPE_SBB",
	"INSTRUCTION_TYPE_INC",
	"INSTRUCTION_TYPE_DEC",
	"INSTRUCTION_TYPE_DIV",
	"INSTRUCTION_TYPE_IDIV",
	"INSTRUCTION_TYPE_NOT",
	"INSTRUCTION_TYPE_NEG",
	"INSTRUCTION_TYPE_STOS",
	"INSTRUCTION_TYPE_LODS",
	"INSTRUCTION_TYPE_SCAS",
	"INSTRUCTION_TYPE_MOVS",
	"INSTRUCTION_TYPE_MOVSX",
	"INSTRUCTION_TYPE_MOVZX",
	"INSTRUCTION_TYPE_CMPS",
	"INSTRUCTION_TYPE_SHX",
	"INSTRUCTION_TYPE_ROX",
	"INSTRUCTION_TYPE_MUL",
	"INSTRUCTION_TYPE_IMUL",
	"INSTRUCTION_TYPE_EIMUL",
	"INSTRUCTION_TYPE_XOR",
	"INSTRUCTION_TYPE_LEA",
	"INSTRUCTION_TYPE_XCHG",
	"INSTRUCTION_TYPE_CMP",
	"INSTRUCTION_TYPE_TEST",
	"INSTRUCTION_TYPE_PUSH",
	"INSTRUCTION_TYPE_AND",
	"INSTRUCTION_TYPE_OR",
	"INSTRUCTION_TYPE_POP",
	"INSTRUCTION_TYPE_JMP",
	"INSTRUCTION_TYPE_JMPC",
	"INSTRUCTION_TYPE_JECXZ",
	"INSTRUCTION_TYPE_SETC",
	"INSTRUCTION_TYPE_MOVC",
	"INSTRUCTION_TYPE_LOOP",
	"INSTRUCTION_TYPE_CALL",
	"INSTRUCTION_TYPE_RET",
	"INSTRUCTION_TYPE_ENTER",
	"INSTRUCTION_TYPE_INT",
	"INSTRUCTION_TYPE_BT",
	"INSTRUCTION_TYPE_BTS",
	"INSTRUCTION_TYPE_BTR",
	"INSTRUCTION_TYPE_BTC",
	"INSTRUCTION_TYPE_BSF",
	"INSTRUCTION_TYPE_BSR",
	"INSTRUCTION_TYPE_BSWAP",
	"INSTRUCTION_TYPE_SGDT",
	"INSTRUCTION_TYPE_SIDT",
	"INSTRUCTION_TYPE_SLDT",
	"INSTRUCTION_TYPE_LFP",
	"INSTRUCTION_TYPE_CLD",
	"INSTRUCTION_TYPE_STD",
	"INSTRUCTION_TYPE_XLAT",
	"INSTRUCTION_TYPE_FCMOVC",
	"INSTRUCTION_TYPE_FADD",
	"INSTRUCTION_TYPE_FADDP",
	"INSTRUCTION_TYPE_FIADD",
	"INSTRUCTION_TYPE_FSUB",
	"INSTRUCTION_TYPE_FSUBP",
	"INSTRUCTION_TYPE_FISUB",
	"INSTRUCTION_TYPE_FSUBR",
	"INSTRUCTION_TYPE_FSUBRP",
	"INSTRUCTION_TYPE_FISUBR",
	"INSTRUCTION_TYPE_FMUL",
	"INSTRUCTION_TYPE_FMULP",
	"INSTRUCTION_TYPE_FIMUL",
	"INSTRUCTION_TYPE_FDIV",
	"INSTRUCTION_TYPE_FDIVP",
	"INSTRUCTION_TYPE_FDIVR",
	"INSTRUCTION_TYPE_FDIVRP",
	"INSTRUCTION_TYPE_FIDIV",
	"INSTRUCTION_TYPE_FIDIVR",
	"INSTRUCTION_TYPE_FCOM",
	"INSTRUCTION_TYPE_FCOMP",
	"INSTRUCTION_TYPE_FCOMPP",
	"INSTRUCTION_TYPE_FCOMI",
	"INSTRUCTION_TYPE_FCOMIP",
	"INSTRUCTION_TYPE_FUCOM",
	"INSTRUCTION_TYPE_FUCOMP",
	"INSTRUCTION_TYPE_FUCOMPP",
	"INSTRUCTION_TYPE_FUCOMI",
	"INSTRUCTION_TYPE_FUCOMIP",
	"INSTRUCTION_TYPE_FST",
	"INSTRUCTION_TYPE_FSTP",
	"INSTRUCTION_TYPE_FIST",
	"INSTRUCTION_TYPE_FISTP",
	"INSTRUCTION_TYPE_FISTTP",
	"INSTRUCTION_TYPE_FLD",
	"INSTRUCTION_TYPE_FILD",
	"INSTRUCTION_TYPE_FICOM",
	"INSTRUCTION_TYPE_FICOMP",
	"INSTRUCTION_TYPE_FFREE",
	"INSTRUCTION_TYPE_FFREEP",
	"INSTRUCTION_TYPE_FXCH",
	"INSTRUCTION_TYPE_SYSENTER",
	"INSTRUCTION_TYPE_FPU_CTRL",
	"INSTRUCTION_TYPE_FPU",

	"INSTRUCTION_TYPE_MMX",

	"INSTRUCTION_TYPE_SSE",

	"INSTRUCTION_TYPE_OTHER",
	"INSTRUCTION_TYPE_PRIV",
    NULL };

/*
    Operand types borrowed from
    "libdasm.h"
*/
char *operand_types[] = {
	"OPERAND_TYPE_NONE",
	"OPERAND_TYPE_MEMORY",
	"OPERAND_TYPE_REGISTER",
	"OPERAND_TYPE_IMMEDIATE",
    NULL };

/*
    Registers borrowed from
    "libdasm.h"
*/
char *registers[] = {
    "REGISTER_EAX",
    "REGISTER_ECX",
    "REGISTER_EDX",
    "REGISTER_EBX",
    "REGISTER_ESP",
    "REGISTER_EBP",
    "REGISTER_ESI",
    "REGISTER_EDI",
    "REGISTER_NOP",
    NULL };


/*
    Register types borrowed from
    "libdasm.h"
*/
char *register_types[] = {
    "REGISTER_TYPE_GEN",
    "REGISTER_TYPE_SEGMENT",
    "REGISTER_TYPE_DEBUG",
    "REGISTER_TYPE_CONTROL",
    "REGISTER_TYPE_TEST",
    "REGISTER_TYPE_XMM",
    "REGISTER_TYPE_MMX",
    "REGISTER_TYPE_FPU",
    NULL };


PyObject *module;   // Main module Python object


/*
    Check whether we got a Python Object
*/
PyObject *check_object(PyObject *pObject)
{
	PyObject *pException;
	
	if(!pObject) {
		pException = PyErr_Occurred();
		if(pException)
            PyErr_Print();
        return NULL;
	}
    
    return pObject;
}


/*
    Assign an attribute "attr" named "name" to an object "obj"
*/
void assign_attribute(PyObject *obj, char *name, PyObject *attr)
{
    PyObject_SetAttrString(obj, name, attr);
    Py_DECREF(attr);
}


/*
    Get an attribute named "attr_name" from object "obj"
    The function steals the reference! note the decrement of
    the reference count.
*/
PyObject *get_attribute(PyObject *obj, char *attr_name)
{
    PyObject *pObj;
    
    pObj = PyObject_GetAttrString(obj, attr_name);
	if(!check_object(pObj)) {
        PyErr_SetString(PyExc_ValueError, "Can't get attribute from object");
        return NULL;
    }
    
    Py_DECREF(pObj);
    return pObj;
}


/*
    Get an Long attribute named "attr_name" from object "obj" and
    return it as a "long int"
*/
long int get_long_attribute(PyObject *o, char *attr_name)
{
    PyObject *pObj;
    
    pObj = get_attribute(o, attr_name);
	if(!pObj)
        return 0;
        
    return PyLong_AsLong(pObj);;
}


/*
    Create a new class and take care of decrementing references.
*/
PyObject *create_class(char *class_name)
{
    PyObject *pClass;
    PyObject *pClassDict = PyDict_New();
    PyObject *pClassName = PyString_FromString(class_name);
    
    pClass = PyClass_New(NULL, pClassDict, pClassName);
    if(!check_object(pClass))
        return NULL;
        
    Py_DECREF(pClassDict);
    Py_DECREF(pClassName);
    
    return pClass;
}


/*
    Create an "Inst" Python object from an INST structure.
*/
PyObject *create_inst_object(INST *pinst)
{
    PyObject *pPInst = create_class("Inst");
    
    if(!pPInst)
        return NULL;

    assign_attribute(pPInst, "type", PyLong_FromLong(pinst->type));
    assign_attribute(pPInst, "mnemonic", PyString_FromString(pinst->mnemonic));
    assign_attribute(pPInst, "flags1", PyLong_FromLong(pinst->flags1));
    assign_attribute(pPInst, "flags2", PyLong_FromLong(pinst->flags2));
    assign_attribute(pPInst, "flags3", PyLong_FromLong(pinst->flags3));
    assign_attribute(pPInst, "modrm", PyLong_FromLong(pinst->modrm));
    
    return pPInst;
}

/*
    Fill an INST structure from the data in an "Inst" Python object.
*/
void fill_inst_structure(PyObject *pPInst, PINST *_pinst)
{
    ssize_t mnemonic_length;
    PINST pinst;
    
    if(!pPInst || !_pinst)
        return;
        
    *_pinst = (PINST)calloc(1, sizeof(INST));
    pinst = *_pinst;
    if(!pinst) {
		PyErr_SetString(PyExc_MemoryError, "Can't allocate memory");
		return;
	}
    
    pinst->type = get_long_attribute(pPInst, "type");
    
    PyString_AsStringAndSize(
        get_attribute(pPInst, "mnemonic"),
        (void *)&pinst->mnemonic, &mnemonic_length);


    pinst->flags1 = get_long_attribute(pPInst, "flags1");
    pinst->flags2 = get_long_attribute(pPInst, "flags2");
    pinst->flags3 = get_long_attribute(pPInst, "flags3");
    pinst->modrm = get_long_attribute(pPInst, "modrm");
}


/*
    Create an "Operand" Python object from an OPERAND structure.
*/
PyObject *create_operand_object(OPERAND *op)
{
    PyObject *pOperand = create_class("Operand");
    
    if(!pOperand)
        return NULL;

    assign_attribute(pOperand, "type", PyLong_FromLong(op->type));
    assign_attribute(pOperand, "reg", PyLong_FromLong(op->reg));
    assign_attribute(pOperand, "basereg", PyLong_FromLong(op->basereg));
    assign_attribute(pOperand, "indexreg", PyLong_FromLong(op->indexreg));
    assign_attribute(pOperand, "scale", PyLong_FromLong(op->scale));
    assign_attribute(pOperand, "dispbytes", PyLong_FromLong(op->dispbytes));
    assign_attribute(pOperand, "dispoffset", PyLong_FromLong(op->dispoffset));
    assign_attribute(pOperand, "immbytes", PyLong_FromLong(op->immbytes));
    assign_attribute(pOperand, "immoffset", PyLong_FromLong(op->immoffset));
    assign_attribute(pOperand, "sectionbytes", PyLong_FromLong(op->sectionbytes));
    assign_attribute(pOperand, "section", PyLong_FromLong(op->section));
    assign_attribute(pOperand, "displacement", PyLong_FromLong(op->displacement));
    assign_attribute(pOperand, "immediate", PyLong_FromLong(op->immediate));
    assign_attribute(pOperand, "flags", PyLong_FromLong(op->flags));
    
    return pOperand;
}


/*
    Fill an OPERAND structure from the data in an "Operand" Python object.
*/
void fill_operand_structure(PyObject *pOperand, OPERAND *op)
{
    if(!pOperand || !op)
        return;
        
    op->type = get_long_attribute(pOperand, "type");
    op->reg = get_long_attribute(pOperand, "reg");
    op->basereg = get_long_attribute(pOperand, "basereg");
    op->indexreg = get_long_attribute(pOperand, "indexreg");
    op->scale = get_long_attribute(pOperand, "scale");
    op->dispbytes = get_long_attribute(pOperand, "dispbytes");
    op->dispoffset = get_long_attribute(pOperand, "dispoffset");
    op->immbytes = get_long_attribute(pOperand, "immbytes");
    op->immoffset = get_long_attribute(pOperand, "immoffset");
    op->sectionbytes = get_long_attribute(pOperand, "sectionbytes");
    op->section = get_long_attribute(pOperand, "section");
    op->displacement = get_long_attribute(pOperand, "displacement");
    op->immediate = get_long_attribute(pOperand, "immediate");
    op->flags = get_long_attribute(pOperand, "flags");
}


/*
    Create an "Instruction" Python object from an INSTRUCTION structure.
*/
PyObject *create_instruction_object(INSTRUCTION *insn)
{
    PyObject *pInstruction = create_class("Instruction");

    if(!pInstruction)
        return NULL;
    
    assign_attribute(pInstruction, "length", PyLong_FromLong(insn->length));
    assign_attribute(pInstruction, "type", PyLong_FromLong(insn->type));
    assign_attribute(pInstruction, "mode", PyLong_FromLong(insn->mode));
    assign_attribute(pInstruction, "opcode", PyLong_FromLong(insn->opcode));
    assign_attribute(pInstruction, "modrm", PyLong_FromLong(insn->modrm));
    assign_attribute(pInstruction, "sib", PyLong_FromLong(insn->sib));
    assign_attribute(pInstruction, "extindex", PyLong_FromLong(insn->extindex));
    assign_attribute(pInstruction, "fpuindex", PyLong_FromLong(insn->fpuindex));
    assign_attribute(pInstruction, "dispbytes", PyLong_FromLong(insn->dispbytes));
    assign_attribute(pInstruction, "immbytes", PyLong_FromLong(insn->immbytes));
    assign_attribute(pInstruction, "sectionbytes", PyLong_FromLong(insn->sectionbytes));
    assign_attribute(pInstruction, "op1", create_operand_object(&insn->op1));
    assign_attribute(pInstruction, "op2", create_operand_object(&insn->op2));
    assign_attribute(pInstruction, "op3", create_operand_object(&insn->op3));
    assign_attribute(pInstruction, "ptr", create_inst_object(insn->ptr));
    assign_attribute(pInstruction, "flags", PyLong_FromLong(insn->flags));
        
    return pInstruction;
}


/*
    Fill an INSTRUCTION structure from the data in an "Instruction" Python object.
*/
void fill_instruction_structure(PyObject *pInstruction, INSTRUCTION *insn)
{
    insn->length = get_long_attribute(pInstruction, "length");
    insn->type = get_long_attribute(pInstruction, "type");
    insn->mode = get_long_attribute(pInstruction, "mode");
    insn->opcode = get_long_attribute(pInstruction, "opcode");
    insn->modrm = get_long_attribute(pInstruction, "modrm");
    insn->sib = get_long_attribute(pInstruction, "sib");
    insn->extindex = get_long_attribute(pInstruction, "extindex");
    insn->fpuindex = get_long_attribute(pInstruction, "fpuindex");
    insn->dispbytes = get_long_attribute(pInstruction, "dispbytes");
    insn->immbytes = get_long_attribute(pInstruction, "immbytes");
    insn->sectionbytes = get_long_attribute(pInstruction, "sectionbytes");
    insn->flags = get_long_attribute(pInstruction, "flags");
    fill_operand_structure(get_attribute(pInstruction, "op1"), &insn->op1);
    fill_operand_structure(get_attribute(pInstruction, "op2"), &insn->op2);
    fill_operand_structure(get_attribute(pInstruction, "op3"), &insn->op3);
    fill_inst_structure(get_attribute(pInstruction, "ptr"), &insn->ptr);
}

/*
    Python counterpart of libdasm's "get_instruction"
*/
#define GET_INSTRUCTION_DOCSTRING                                               \
    "Decode an instruction from the given buffer.\n\n"                          \
    "Takes in a string containing the data to disassemble and the\nmode, "      \
    "either MODE_16 or MODE_32. Returns an Instruction object or \nNone if "    \
    "the instruction can't be disassembled."
    
PyObject *pydasm_get_instruction(PyObject *self, PyObject *args)
{
	PyObject *pBuffer, *pMode;
	INSTRUCTION insn;
	int size, mode;
	ssize_t data_length;
    char *data;

    
	if(!args || PyObject_Length(args)!=2) {
		PyErr_SetString(PyExc_TypeError,
			"Invalid number of arguments, 2 expected: (data, mode)");
		return NULL;
	}
	
	pBuffer = PyTuple_GetItem(args, 0);
	if(!check_object(pBuffer)) {
        PyErr_SetString(PyExc_ValueError, "Can't get buffer from arguments");
    }
    
	pMode = PyTuple_GetItem(args, 1);
	if(!check_object(pMode)) {
        PyErr_SetString(PyExc_ValueError, "Can't get mode from arguments");
    }
    mode = PyLong_AsLong(pMode);

    PyString_AsStringAndSize(pBuffer, &data, &data_length);
	
	size = get_instruction(&insn, (unsigned char *)data, mode);
    
    if(!size) {    
        Py_INCREF(Py_None);
        return Py_None;
    }

    return create_instruction_object(&insn);
}


/*
    Python counterpart of libdasm's "get_instruction_string"
*/
#define GET_INSTRUCTION_STRING_DOCSTRING                                    \
    "Transform an instruction object into its string representation.\n\n"   \
    "The function takes an Instruction object; its format, either \n"       \
    "FORMAT_INTEL or FORMAT_ATT and finally an offset (refer to \n"         \
    "libdasm for meaning). Returns a string representation of the \n"       \
    "disassembled instruction."
    
PyObject *pydasm_get_instruction_string(PyObject *self, PyObject *args)
{
	PyObject *pInstruction, *pFormat, *pOffset, *pStr;
	INSTRUCTION insn;
	unsigned long int offset, format;
    char *data;

    
	if(!args || PyObject_Length(args)!=3) {
		PyErr_SetString(PyExc_TypeError,
			"Invalid number of arguments, 3 expected: (instruction, format, offset)");
		return NULL;
	}
	
	pInstruction = PyTuple_GetItem(args, 0);
	if(!check_object(pInstruction)) {
        PyErr_SetString(PyExc_ValueError, "Can't get instruction from arguments");
    }
    if(pInstruction == Py_None) {
        Py_INCREF(Py_None);
        return Py_None;
    }
    memset(&insn, 0, sizeof(INSTRUCTION));
    fill_instruction_structure(pInstruction, &insn);
    
	pFormat = PyTuple_GetItem(args, 1);
	if(!check_object(pFormat)) {
        PyErr_SetString(PyExc_ValueError, "Can't get format from arguments");
    }
    format = PyLong_AsLong(pFormat);
	
	pOffset = PyTuple_GetItem(args, 2);
	if(!check_object(pOffset)) {
        PyErr_SetString(PyExc_ValueError, "Can't get offset from arguments");
    }
    offset = PyLong_AsLong(pOffset);

    data = (char *)calloc(1, INSTRUCTION_STR_BUFFER_LENGTH);
    if(!data) {
		PyErr_SetString(PyExc_MemoryError, "Can't allocate memory");
		return NULL;
	}
    
    if(!get_instruction_string(&insn, format, offset,
        data, INSTRUCTION_STR_BUFFER_LENGTH))
    {    
        Py_INCREF(Py_None);
        return Py_None;
    }
    
    pStr = PyString_FromStringAndSize(data, strlen(data));    
    free(insn.ptr);
    free(data);
    
    return pStr;
}


/*
    Python counterpart of libdasm's "get_mnemonic_string"
*/
#define GET_MNEMONIC_STRING_DOCSTRING                                       \
    "Transform an instruction object's mnemonic into its string representation.\n\n"    \
    "The function takes an Instruction object and its format, either \n"    \
    "FORMAT_INTEL or FORMAT_ATT. Returns a string representation of the \n" \
    "mnemonic."
    
PyObject *pydasm_get_mnemonic_string(PyObject *self, PyObject *args)
{
	PyObject *pInstruction, *pFormat, *pStr;
	INSTRUCTION insn;
	unsigned long int format;
    char *data;

	if(!args || PyObject_Length(args)!=2) {
		PyErr_SetString(PyExc_TypeError,
			"Invalid number of arguments, 3 expected: (instruction, format)");
		return NULL;
	}
	
	pInstruction = PyTuple_GetItem(args, 0);
	if(!check_object(pInstruction)) {
        PyErr_SetString(PyExc_ValueError, "Can't get instruction from arguments");
    }
    fill_instruction_structure(pInstruction, &insn);
    
	pFormat = PyTuple_GetItem(args, 1);
	if(!check_object(pFormat)) {
        PyErr_SetString(PyExc_ValueError, "Can't get format from arguments");
    }
    format = PyLong_AsLong(pFormat);
	
    data = (char *)calloc(1, INSTRUCTION_STR_BUFFER_LENGTH);
    if(!data) {
		PyErr_SetString(PyExc_MemoryError, "Can't allocate memory");
		return NULL;
	}
    
    get_mnemonic_string(&insn, format, data, INSTRUCTION_STR_BUFFER_LENGTH);
      
    pStr = PyString_FromStringAndSize(data, strlen(data));
    free(data);
    
    return pStr;
}


/*
    Python counterpart of libdasm's "get_operand_string"
*/
#define GET_OPERAND_STRING_DOCSTRING                                        \
    "Transform an instruction object's operand into its string representation.\n\n"    \
    "The function takes an Instruction object; the operand index (0,1,2);\n"\
    " its format, either FORMAT_INTEL or FORMAT_ATT and finally an offset\n"\
    "(refer to libdasm for meaning). Returns a string representation of \n" \
    "the disassembled operand."
    
PyObject *pydasm_get_operand_string(PyObject *self, PyObject *args)
{
	PyObject *pInstruction, *pFormat, *pOffset, *pOpIndex, *pStr;
	INSTRUCTION insn;
	unsigned long int offset, format, op_idx;
    char *data;

    
	if(!args || PyObject_Length(args)!=4) {
		PyErr_SetString(PyExc_TypeError,
			"Invalid number of arguments, 4 expected: (instruction, operand index, format, offset)");
		return NULL;
	}
	
	pInstruction = PyTuple_GetItem(args, 0);
	if(!check_object(pInstruction)) {
        PyErr_SetString(PyExc_ValueError, "Can't get instruction from arguments");
    }
    memset(&insn, 0, sizeof(INSTRUCTION));
    fill_instruction_structure(pInstruction, &insn);
    
	pOpIndex = PyTuple_GetItem(args, 1);
	if(!check_object(pOpIndex)) {
        PyErr_SetString(PyExc_ValueError, "Can't get operand index from arguments");
    }
    op_idx = PyLong_AsLong(pOpIndex);
	
    pFormat = PyTuple_GetItem(args, 2);
	if(!check_object(pFormat)) {
        PyErr_SetString(PyExc_ValueError, "Can't get format from arguments");
    }
    format = PyLong_AsLong(pFormat);
	
	pOffset = PyTuple_GetItem(args, 3);
	if(!check_object(pOffset)) {
        PyErr_SetString(PyExc_ValueError, "Can't get offset from arguments");
    }
    offset = PyLong_AsLong(pOffset);

    data = (char *)calloc(1, INSTRUCTION_STR_BUFFER_LENGTH);
    if(!data) {
		PyErr_SetString(PyExc_MemoryError, "Can't allocate memory");
		return NULL;
	}
    
    if(!get_operand_string(&insn, &(insn.op1)+op_idx,
        format, offset, data, INSTRUCTION_STR_BUFFER_LENGTH))
    {    
        Py_INCREF(Py_None);
        return Py_None;
    }
    
    pStr = PyString_FromStringAndSize(data, strlen(data));
    free(data);
    
    return pStr;
}


/*
    Python counterpart of libdasm's "get_register_type"
*/
#define GET_REGISTER_TYPE_DOCSTRING                                         \
    "Get the type of the register used by the operand.\n\n"                 \
    "The function takes an Operand object and returns a Long representing\n"\
    "the type of the register."
    
PyObject *pydasm_get_register_type(PyObject *self, PyObject *args)
{
	PyObject *pOperand;
    OPERAND op;

	if(!args || PyObject_Length(args)!=1) {
		PyErr_SetString(PyExc_TypeError,
			"Invalid number of arguments, 1 expected: (operand)");
		return NULL;
	}
	
	pOperand = PyTuple_GetItem(args, 0);
	if(!check_object(pOperand)) {
        PyErr_SetString(PyExc_ValueError, "Can't get instruction from arguments");
    }
    memset(&op, 0, sizeof(OPERAND));
    fill_operand_structure(pOperand, &op);
        
    return PyLong_FromLong(get_register_type(&op));
}


/*
    Map all the exported methods.
*/
static PyMethodDef pydasmMethods[] = {
	{"get_instruction", pydasm_get_instruction, METH_VARARGS,
	GET_INSTRUCTION_DOCSTRING},
	{"get_instruction_string", pydasm_get_instruction_string, METH_VARARGS,
	GET_INSTRUCTION_STRING_DOCSTRING},
	{"get_mnemonic_string", pydasm_get_mnemonic_string, METH_VARARGS,
	GET_MNEMONIC_STRING_DOCSTRING},
	{"get_operand_string", pydasm_get_operand_string, METH_VARARGS,
	GET_OPERAND_STRING_DOCSTRING},
	{"get_register_type", pydasm_get_register_type, METH_VARARGS,
	GET_REGISTER_TYPE_DOCSTRING},
	{NULL, NULL, 0, NULL}
};


/*
    Init the module, set constants.
*/
PyMODINIT_FUNC initpydasm(void)
{
    int i;
    PyObject *pModule;
    
	pModule = Py_InitModule("pydasm", pydasmMethods);

    assign_attribute(pModule, "FORMAT_ATT", PyLong_FromLong(0));
    assign_attribute(pModule, "FORMAT_INTEL", PyLong_FromLong(1));

    assign_attribute(pModule, "MODE_16", PyLong_FromLong(1));
    assign_attribute(pModule, "MODE_32", PyLong_FromLong(0));
    
    for(i=0; instruction_types[i]; i++)
        assign_attribute(pModule, instruction_types[i], PyLong_FromLong(i));
    
    for(i=0; operand_types[i]; i++)
        assign_attribute(pModule, operand_types[i], PyLong_FromLong(i));

    for(i=0; registers[i]; i++)
        assign_attribute(pModule, registers[i], PyLong_FromLong(i));
        
    for(i=0; register_types[i]; i++)
        assign_attribute(pModule, register_types[i], PyLong_FromLong(i+1));

}


int main(int agrc, char *argv[])
{
	Py_SetProgramName(argv[0]);
	
	Py_Initialize();
	
	initpydasm();

	return 0;
}

