

pub trait TransSliceLen{
    fn slice_len(&self)->usize{
        return std::mem::size_of_val(self);
    }
}

pub trait TransSlice: TransSliceLen+Default{
    fn into_slice(&self)->&[u8]{
        return unsafe {std::slice::from_raw_parts(std::mem::transmute::<&Self, *mut u8>(&self), self.slice_len())};
    }
    fn from_slice(d: &[u8])->Self{
        let t:Self = Self::default();
        unsafe {
            std::ptr::copy(std::mem::transmute::<&u8, *mut u8>(&d[0]), std::mem::transmute::<&Self, *mut u8>(&t), t.slice_len());
        }
        return t;
    }
}

