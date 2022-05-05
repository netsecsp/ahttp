

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 8.00.0603 */
/* at Tue Apr 26 17:24:44 2022
 */
/* Compiler settings for ILogger.idl:
    Oicf, W1, Zp8, env=Win32 (32b run), target_arch=X86 8.00.0603 
    protocol : dce , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */

#pragma warning( disable: 4049 )  /* more than 64k source lines */


/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 475
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif // __RPCNDR_H_VERSION__

#ifndef COM_NO_WINDOWS_H
#include "windows.h"
#include "ole2.h"
#endif /*COM_NO_WINDOWS_H*/

#ifndef __ILogger_h__
#define __ILogger_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

/* Forward Declarations */ 

#ifndef __IAsynLogger_FWD_DEFINED__
#define __IAsynLogger_FWD_DEFINED__
typedef interface IAsynLogger IAsynLogger;

#endif 	/* __IAsynLogger_FWD_DEFINED__ */


#ifndef __IAsynLoggerFactory_FWD_DEFINED__
#define __IAsynLoggerFactory_FWD_DEFINED__
typedef interface IAsynLoggerFactory IAsynLoggerFactory;

#endif 	/* __IAsynLoggerFactory_FWD_DEFINED__ */


/* header files for imported files */
#include "IAsynFrame.h"

#ifdef __cplusplus
extern "C"{
#endif 


/* interface __MIDL_itf_ILogger_0000_0000 */
/* [local] */ 

#pragma pack(push, 1)


extern RPC_IF_HANDLE __MIDL_itf_ILogger_0000_0000_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_ILogger_0000_0000_v0_0_s_ifspec;

#ifndef __IAsynLogger_INTERFACE_DEFINED__
#define __IAsynLogger_INTERFACE_DEFINED__

/* interface IAsynLogger */
/* [unique][helpstring][uuid][object] */ 


EXTERN_C const IID IID_IAsynLogger;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("C2E43C05-2E46-4e28-8369-3AD0DA93C966")
    IAsynLogger : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE IsEnabled( 
            /* [in] */ uint32_t level) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Logs( 
            /* [in] */ uint32_t level,
            /* [in] */ STRING file,
            /* [in] */ uint32_t line,
            /* [in] */ STRING text) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Dump( 
            /* [in] */ uint32_t level,
            /* [in] */ STRING hint,
            /* [in] */ STRING data) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IAsynLoggerVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IAsynLogger * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IAsynLogger * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IAsynLogger * This);
        
        HRESULT ( STDMETHODCALLTYPE *IsEnabled )( 
            IAsynLogger * This,
            /* [in] */ uint32_t level);
        
        HRESULT ( STDMETHODCALLTYPE *Logs )( 
            IAsynLogger * This,
            /* [in] */ uint32_t level,
            /* [in] */ STRING file,
            /* [in] */ uint32_t line,
            /* [in] */ STRING text);
        
        HRESULT ( STDMETHODCALLTYPE *Dump )( 
            IAsynLogger * This,
            /* [in] */ uint32_t level,
            /* [in] */ STRING hint,
            /* [in] */ STRING data);
        
        END_INTERFACE
    } IAsynLoggerVtbl;

    interface IAsynLogger
    {
        CONST_VTBL struct IAsynLoggerVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IAsynLogger_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IAsynLogger_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IAsynLogger_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IAsynLogger_IsEnabled(This,level)	\
    ( (This)->lpVtbl -> IsEnabled(This,level) ) 

#define IAsynLogger_Logs(This,level,file,line,text)	\
    ( (This)->lpVtbl -> Logs(This,level,file,line,text) ) 

#define IAsynLogger_Dump(This,level,hint,data)	\
    ( (This)->lpVtbl -> Dump(This,level,hint,data) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IAsynLogger_INTERFACE_DEFINED__ */


#ifndef __IAsynLoggerFactory_INTERFACE_DEFINED__
#define __IAsynLoggerFactory_INTERFACE_DEFINED__

/* interface IAsynLoggerFactory */
/* [unique][helpstring][uuid][object] */ 


EXTERN_C const IID IID_IAsynLoggerFactory;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("0CC86662-03BA-48b1-9111-BB3242C34D41")
    IAsynLoggerFactory : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE SetEnable( 
            /* [in] */ STRING MName,
            /* [in] */ BOOL bEnabled) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetOutput( 
            /* [in] */ IDataTransmit *target) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE CreateAsynLogger( 
            /* [in] */ STRING MName,
            /* [in] */ STRING Clazz,
            /* [out] */ IAsynLogger **ppAsynLogger) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IAsynLoggerFactoryVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IAsynLoggerFactory * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IAsynLoggerFactory * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IAsynLoggerFactory * This);
        
        HRESULT ( STDMETHODCALLTYPE *SetEnable )( 
            IAsynLoggerFactory * This,
            /* [in] */ STRING MName,
            /* [in] */ BOOL bEnabled);
        
        HRESULT ( STDMETHODCALLTYPE *SetOutput )( 
            IAsynLoggerFactory * This,
            /* [in] */ IDataTransmit *target);
        
        HRESULT ( STDMETHODCALLTYPE *CreateAsynLogger )( 
            IAsynLoggerFactory * This,
            /* [in] */ STRING MName,
            /* [in] */ STRING Clazz,
            /* [out] */ IAsynLogger **ppAsynLogger);
        
        END_INTERFACE
    } IAsynLoggerFactoryVtbl;

    interface IAsynLoggerFactory
    {
        CONST_VTBL struct IAsynLoggerFactoryVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IAsynLoggerFactory_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IAsynLoggerFactory_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IAsynLoggerFactory_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IAsynLoggerFactory_SetEnable(This,MName,bEnabled)	\
    ( (This)->lpVtbl -> SetEnable(This,MName,bEnabled) ) 

#define IAsynLoggerFactory_SetOutput(This,target)	\
    ( (This)->lpVtbl -> SetOutput(This,target) ) 

#define IAsynLoggerFactory_CreateAsynLogger(This,MName,Clazz,ppAsynLogger)	\
    ( (This)->lpVtbl -> CreateAsynLogger(This,MName,Clazz,ppAsynLogger) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IAsynLoggerFactory_INTERFACE_DEFINED__ */


/* interface __MIDL_itf_ILogger_0000_0002 */
/* [local] */ 

#pragma pack(pop)


extern RPC_IF_HANDLE __MIDL_itf_ILogger_0000_0002_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_ILogger_0000_0002_v0_0_s_ifspec;

/* Additional Prototypes for ALL interfaces */

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


