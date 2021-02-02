use core::convert::TryInto;
use alloc::vec::Vec;
use crate::Error;

pub struct Collect<T> {
    pub(crate) index: usize,
    pub(crate) msgs: Vec<Option<T>>,
}

impl<T: Clone> Collect<T> {
    const ALG: &'static str = "signature::aggregated::internal::Collect";

    pub fn new(count: usize, index: usize) -> Collect<T> {
        assert!(index < count);
        let mut msgs = Vec::new();
        msgs.resize(count - 1, None);
        Self {
            index,
            msgs,
        }
    }

    pub fn update<U: Into<T>>(&mut self, msg_index: usize, msg: U) -> Result<(), Error> {
        if msg_index <= self.msgs.len() {
            if msg_index != self.index {
                let i = if msg_index < self.index {
                    msg_index
                } else {
                    msg_index - 1
                };
                if self.msgs[i].is_none() {
                    self.msgs[i] = Some(msg.into());
                    Ok(())
                } else {
                    Err(Error::InvalidArgumentError{
                        alg: Self::ALG,
                        expected: "unique msg",
                    })
                }
            } else {
                Err(Error::InvalidArgumentError{
                    alg: Self::ALG,
                    expected: "msg_index != index",
                })
            }
        } else {
            Err(Error::InvalidArgumentError{
                alg: Self::ALG,
                expected: "msg_index < count",
            })
        }
    }

    pub fn try_update<U: TryInto<T, Error = crate::Error>>(&mut self, msg_index: usize, msg: U) -> Result<(), Error> {
        if msg_index <= self.msgs.len() {
            if msg_index != self.index {
                let i = if msg_index < self.index {
                    msg_index
                } else {
                    msg_index - 1
                };
                if self.msgs[i].is_none() {
                    self.msgs[i] = Some(msg.try_into()?);
                    Ok(())
                } else {
                    Err(Error::InvalidArgumentError{
                        alg: Self::ALG,
                        expected: "unique msg",
                    })
                }
            } else {
                Err(Error::InvalidArgumentError{
                    alg: Self::ALG,
                    expected: "msg_index != index",
                })
            }
        } else {
            Err(Error::InvalidArgumentError{
                alg: Self::ALG,
                expected: "msg_index < count",
            })
        }
    }

    pub fn done(self) -> Result<impl Iterator<Item = T>, Error> {
        if self.msgs.iter().find(|msg| msg.is_none()).is_none() {
            Ok(self.msgs.into_iter().filter_map(|x| x))
        } else {
            Err(Error::InvalidArgumentError{
                alg: Self::ALG,
                expected: "the only msg",
            })
        }
    }
}
