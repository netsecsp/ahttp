

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 8.00.0603 */
/* at Tue Apr 26 17:24:50 2022
 */
/* Compiler settings for IDns.idl:
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

#ifndef __IDns_h__
#define __IDns_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

/* Forward Declarations */ 

#ifndef __IDnsHostInfo_FWD_DEFINED__
#define __IDnsHostInfo_FWD_DEFINED__
typedef interface IDnsHostInfo IDnsHostInfo;

#endif 	/* __IDnsHostInfo_FWD_DEFINED__ */


#ifndef __IDnsHostZone_FWD_DEFINED__
#define __IDnsHostZone_FWD_DEFINED__
typedef interface IDnsHostZone IDnsHostZone;

#endif 	/* __IDnsHostZone_FWD_DEFINED__ */


/* header files for imported files */
#include "IAsynFrame.h"

#ifdef __cplusplus
extern "C"{
#endif 


/* interface __MIDL_itf_IDns_0000_0000 */
/* [local] */ 

#pragma pack(push, 1)


extern RPC_IF_HANDLE __MIDL_itf_IDns_0000_0000_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_IDns_0000_0000_v0_0_s_ifspec;

#ifndef __IDnsHostInfo_INTERFACE_DEFINED__
#define __IDnsHostInfo_INTERFACE_DEFINED__

/* interface IDnsHostInfo */
/* [unique][helpstring][uuid][object] */ 


EXTERN_C const IID IID_IDnsHostInfo;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("87EFBDAA-579E-4508-986C-C36C60B5DCB6")
    IDnsHostInfo : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE Get( 
            /* [out] */ STRING *Host,
            /* [out] */ uint32_t *af,
            /* [out] */ uint16_t *id) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Set( 
            /* [in] */ STRING Real) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IDnsHostInfoVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IDnsHostInfo * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IDnsHostInfo * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IDnsHostInfo * This);
        
        HRESULT ( STDMETHODCALLTYPE *Get )( 
            IDnsHostInfo * This,
            /* [out] */ STRING *Host,
            /* [out] */ uint32_t *af,
            /* [out] */ uint16_t *id);
        
        HRESULT ( STDMETHODCALLTYPE *Set )( 
            IDnsHostInfo * This,
            /* [in] */ STRING Real);
        
        END_INTERFACE
    } IDnsHostInfoVtbl;

    interface IDnsHostInfo
    {
        CONST_VTBL struct IDnsHostInfoVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IDnsHostInfo_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IDnsHostInfo_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IDnsHostInfo_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IDnsHostInfo_Get(This,Host,af,id)	\
    ( (This)->lpVtbl -> Get(This,Host,af,id) ) 

#define IDnsHostInfo_Set(This,Real)	\
    ( (This)->lpVtbl -> Set(This,Real) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IDnsHostInfo_INTERFACE_DEFINED__ */


#ifndef __IDnsHostZone_INTERFACE_DEFINED__
#define __IDnsHostZone_INTERFACE_DEFINED__

/* interface IDnsHostZone */
/* [unique][helpstring][uuid][object] */ 


EXTERN_C const IID IID_IDnsHostZone;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("73256D0B-76A0-47e0-B40D-B0BC4B279428")
    IDnsHostZone : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE Get( 
            /* [in] */ STRING Host,
            /* [in] */ uint32_t type,
            /* [out] */ IStringsStack **ppObject) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Set( 
            /* [in] */ STRING Host,
            /* [in] */ uint32_t type,
            /* [in] */ STRING Real,
            /* [size_is][in] */ STRING *Val,
            /* [in] */ uint32_t Count,
            /* [in] */ uint32_t ttl) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Reset( 
            /* [in] */ uint32_t type) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IDnsHostZoneVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IDnsHostZone * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IDnsHostZone * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IDnsHostZone * This);
        
        HRESULT ( STDMETHODCALLTYPE *Get )( 
            IDnsHostZone * This,
            /* [in] */ STRING Host,
            /* [in] */ uint32_t type,
            /* [out] */ IStringsStack **ppObject);
        
        HRESULT ( STDMETHODCALLTYPE *Set )( 
            IDnsHostZone * This,
            /* [in] */ STRING Host,
            /* [in] */ uint32_t type,
            /* [in] */ STRING Real,
            /* [size_is][in] */ STRING *Val,
            /* [in] */ uint32_t Count,
            /* [in] */ uint32_t ttl);
        
        HRESULT ( STDMETHODCALLTYPE *Reset )( 
            IDnsHostZone * This,
            /* [in] */ uint32_t type);
        
        END_INTERFACE
    } IDnsHostZoneVtbl;

    interface IDnsHostZone
    {
        CONST_VTBL struct IDnsHostZoneVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IDnsHostZone_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IDnsHostZone_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IDnsHostZone_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IDnsHostZone_Get(This,Host,type,ppObject)	\
    ( (This)->lpVtbl -> Get(This,Host,type,ppObject) ) 

#define IDnsHostZone_Set(This,Host,type,Real,Val,Count,ttl)	\
    ( (This)->lpVtbl -> Set(This,Host,type,Real,Val,Count,ttl) ) 

#define IDnsHostZone_Reset(This,type)	\
    ( (This)->lpVtbl -> Reset(This,type) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IDnsHostZone_INTERFACE_DEFINED__ */


/* interface __MIDL_itf_IDns_0000_0002 */
/* [local] */ 

#pragma pack(pop)


extern RPC_IF_HANDLE __MIDL_itf_IDns_0000_0002_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_IDns_0000_0002_v0_0_s_ifspec;

/* Additional Prototypes for ALL interfaces */

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


