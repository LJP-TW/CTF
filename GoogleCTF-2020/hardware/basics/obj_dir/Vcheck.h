// Verilated -*- C++ -*-
// DESCRIPTION: Verilator output: Primary design header
//
// This header should be included by all source files instantiating the design.
// The class here is then constructed to instantiate the design.
// See the Verilator manual for examples.

#ifndef _VCHECK_H_
#define _VCHECK_H_  // guard

#include "verilated.h"

//==========

class Vcheck__Syms;

//----------

VL_MODULE(Vcheck) {
  public:
    
    // PORTS
    // The application code writes and reads these signals to
    // propagate new values into/out from the Verilated model.
    VL_IN8(clk,0,0);
    VL_IN8(data,6,0);
    VL_OUT8(open_safe,0,0);
    VL_OUT8(my_memory1,6,0);
    VL_OUT8(my_memory2,6,0);
    VL_OUT8(my_memory3,6,0);
    VL_OUT8(my_memory4,6,0);
    VL_OUT8(my_memory5,6,0);
    VL_OUT8(my_memory6,6,0);
    VL_OUT8(my_memory7,6,0);
    VL_OUT8(my_memory8,6,0);
    VL_OUT64(my_test,55,0);
    VL_OUT64(my_test2,55,0);
    
    // LOCAL SIGNALS
    // Internals; generally not touched by application code
    CData/*2:0*/ check__DOT__idx;
    QData/*55:0*/ check__DOT__magic;
    QData/*55:0*/ check__DOT__kittens;
    CData/*6:0*/ check__DOT__memory[8];
    
    // LOCAL VARIABLES
    // Internals; generally not touched by application code
    CData/*0:0*/ __Vclklast__TOP__clk;
    
    // INTERNAL VARIABLES
    // Internals; generally not touched by application code
    Vcheck__Syms* __VlSymsp;  // Symbol table
    
    // CONSTRUCTORS
  private:
    VL_UNCOPYABLE(Vcheck);  ///< Copying not allowed
  public:
    /// Construct the model; called by application code
    /// The special name  may be used to make a wrapper with a
    /// single model invisible with respect to DPI scope names.
    Vcheck(const char* name = "TOP");
    /// Destroy the model; called (often implicitly) by application code
    ~Vcheck();
    
    // API METHODS
    /// Evaluate the model.  Application must call when inputs change.
    void eval() { eval_step(); }
    /// Evaluate when calling multiple units/models per time step.
    void eval_step();
    /// Evaluate at end of a timestep for tracing, when using eval_step().
    /// Application must call after all eval() and before time changes.
    void eval_end_step() {}
    /// Simulation complete, run final blocks.  Application must call on completion.
    void final();
    
    // INTERNAL METHODS
  private:
    static void _eval_initial_loop(Vcheck__Syms* __restrict vlSymsp);
  public:
    void __Vconfigure(Vcheck__Syms* symsp, bool first);
  private:
    static QData _change_request(Vcheck__Syms* __restrict vlSymsp);
    void _ctor_var_reset() VL_ATTR_COLD;
  public:
    static void _eval(Vcheck__Syms* __restrict vlSymsp);
  private:
#ifdef VL_DEBUG
    void _eval_debug_assertions();
#endif  // VL_DEBUG
  public:
    static void _eval_initial(Vcheck__Syms* __restrict vlSymsp) VL_ATTR_COLD;
    static void _eval_settle(Vcheck__Syms* __restrict vlSymsp) VL_ATTR_COLD;
    static void _initial__TOP__2(Vcheck__Syms* __restrict vlSymsp) VL_ATTR_COLD;
    static void _sequent__TOP__1(Vcheck__Syms* __restrict vlSymsp);
    static void _settle__TOP__3(Vcheck__Syms* __restrict vlSymsp) VL_ATTR_COLD;
} VL_ATTR_ALIGNED(VL_CACHE_LINE_BYTES);

//----------


#endif  // guard
