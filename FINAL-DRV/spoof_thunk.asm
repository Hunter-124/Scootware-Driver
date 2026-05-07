;
; spoof_thunk.asm
; ────────────────────────────────────────────────────────────────────────────
; Naked assembly thunk for return-address stack spoofing.
;
; Build:  ml64 /c spoof_thunk.asm   →   spoof_thunk.obj   (linked into driver)
;
; ─── Frame layout (this is the part the previous version got wrong) ────────
;
; Win64 ABI requires that, at the moment a callee receives control,
;   (rsp & 0xF) == 8   — the implicit slot for the return address —
; AND that the caller has reserved 32 bytes of shadow space at
;   [rsp+8 .. rsp+0x28]
; for the callee to home rcx/rdx/r8/r9.  A simple "push fake_ret; push real_ret;
; jmp target" frame violates BOTH constraints:  the callee writes its rcx home
; over our pushed gadget pointer, and rsp is misaligned, so the first movaps
; in any kernel routine raises #GP → KMODE_EXCEPTION_NOT_HANDLED.
;
; Correct frame, built below (rsp grows down):
;
;     [rsp + 0x00] = gadget       ← target's RET pops this
;     [rsp + 0x08] = scratch       ┐
;     [rsp + 0x10] = scratch       │ shadow space — target may scribble
;     [rsp + 0x18] = scratch       │   rcx/rdx/r8/r9 here freely
;     [rsp + 0x20] = scratch       ┘
;     [rsp + 0x28] = pad           ← keeps gadget's RET aligned, untouched
;     [rsp + 0x30] = real_ret      ← gadget's "add rsp,0x28; ret" pops this
;
; Total reservation: 0x38 (7 qwords).
;
; Why 0x38 and not 0x30?  Alignment.  At thunk entry rsp%16 == 8 (CALL pushed
; one qword).  After "pop rax" rsp%16 == 0.  We need target entry to satisfy
; rsp%16 == 8, so the allocation must be 8 mod 16 → 0x38 works, 0x30 would
; misalign and BSOD.  The extra qword at +0x28 also keeps real_ret outside the
; ABI shadow window so the callee can never overwrite it.
;
; Gadget contract:  g_SpoofedGadget MUST point to the byte sequence
;     48 83 C4 28 C3      ; add rsp, 0x28 ; ret
; (FindRetGadget in syscall_stack_spoof.h locates this pattern in ntoskrnl
; .text — it is a near-universal kernel-function epilogue.)
;
; Unwind walk (what EAC sees):
;     target_func+offset           ← legitimate ntoskrnl frame
;     ntoskrnl!gadget              ← legitimate ntoskrnl frame (in .text)
;     (driver code, unbacked)      ← typically truncated by the unwinder
;
; ─── GLOBAL VARIABLES ──────────────────────────────────────────────────────
;   extern "C" PVOID g_SpoofedTarget;  // real Nt*/Zw* function
;   extern "C" PVOID g_SpoofedGadget;  // → "add rsp,0x28; ret" in ntoskrnl
; ────────────────────────────────────────────────────────────────────────────

.CODE

EXTERN g_SpoofedTarget:QWORD
EXTERN g_SpoofedGadget:QWORD

SpoofCallThunk PROC
    ; [rsp] = real return address (into our unbacked driver code).
    pop     rax                              ; rax  ← real_ret

    mov     r10, qword ptr [g_SpoofedTarget] ; r10  ← real callee
    mov     r11, qword ptr [g_SpoofedGadget] ; r11  ← ntoskrnl gadget

    sub     rsp, 38h                         ; reserve 7 qwords (see header)
    mov     qword ptr [rsp + 30h], rax       ; real_ret  → outside shadow
    mov     qword ptr [rsp +  0h], r11       ; gadget    → target's "ret addr"

    ; rcx/rdx/r8/r9 are still the original arguments — we never touched them.
    ; rax/r10/r11 are volatile per Win64 ABI; no preservation needed.
    jmp     r10
SpoofCallThunk ENDP

END
