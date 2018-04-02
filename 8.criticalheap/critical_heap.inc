; ---------------------------------------------------------------------------

Elf64_Sym       struc ; (sizeof=0x18, align=0x8, mappedto_1)
                                        ; XREF: LOAD:0000000000400388/r
                                        ; LOAD:00000000004003A0/r ...
st_name         dd ?                    ; offset (004006A0)
st_info         db ?
st_other        db ?
st_shndx        dw ?
st_value        dq ?                    ; offset (00000000)
st_size         dq ?
Elf64_Sym       ends

; ---------------------------------------------------------------------------

Elf64_Rela      struc ; (sizeof=0x18, align=0x8, copyof_2)
                                        ; XREF: LOAD:0000000000400868/r
                                        ; LOAD:0000000000400880/r ...
r_offset        dq ?
r_info          dq ?
r_addend        dq ?
Elf64_Rela      ends

; ---------------------------------------------------------------------------

Elf64_Dyn       struc ; (sizeof=0x10, align=0x8, copyof_3)
                                        ; XREF: LOAD:stru_603D38/r
                                        ; LOAD:0000000000603D48/r ...
d_tag           dq ?
d_un            dq ?
Elf64_Dyn       ends

; ---------------------------------------------------------------------------

NormalHeap      struc ; (sizeof=0x48, align=0x8, copyof_6)
heapname        dq ?                    ; offset
isused          dq ?
magicx13371337  dq ?
buf             db 40 dup(?)
zero            dq ?
NormalHeap      ends

; ---------------------------------------------------------------------------

SystemHeap      struc ; (sizeof=0x48, align=0x8, copyof_7)
heapname        dq ?                    ; offset
isused          dq ?
magicx48694869  dq ?
current_dir_name dq ?
secret_of_heap  dq ?
user_of_heap    dq ?                    ; offset
name_of_heap    dq ?                    ; offset
rand_num        dd ?
unused32        dd ?
unused64        dq ?
SystemHeap      ends

; ---------------------------------------------------------------------------

ClockHeap       struc ; (sizeof=0x48, align=0x8, copyof_8)
heapname        dq ?                    ; offset
isused          dq ?
magicxDEADBEEF  dq ?
tmtime          dq ?                    ; offset
year            dd ?
month           dd ?
day             dd ?
hour            dd ?
minute          dd ?
seconds         dd ?
unused          dq 2 dup(?)
ClockHeap       ends

; ---------------------------------------------------------------------------

CustomHeap      struc ; (sizeof=0x48, align=0x8, copyof_9)
                                        ; XREF: .bss:g_AllHeap/r
heapname        dq ?                    ; offset
isused          dq ?
magic           dq ?
unused          dq 6 dup(?)
CustomHeap      ends


