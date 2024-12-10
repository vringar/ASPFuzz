use std::{borrow::Cow, collections::HashSet};

use crate::{MiscMetadata, WriteCatcher, WriteCatcherMetadata};
use libafl::{
    inputs::UsesInput,
    prelude::*,
    prelude::{ExitKind, Feedback, Observer, StateInitializer},
    HasMetadata,
};
use libafl_bolts::{
    tuples::{Handle, Handled, MatchName, MatchNameRef},
    Named,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct WriteCatcherConfig {
    start: u64,
    end: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WriteCatcherObserver {
    c: Option<WriteCatcherConfig>,
    write_catcher: WriteCatcher,
    result: Option<WriteCatcherMetadata>,
}

impl WriteCatcherObserver {
    pub fn new(config: Option<WriteCatcherConfig>) -> Self {
        Self {
            c: config,
            write_catcher: WriteCatcher {},
            result: None,
        }
    }
}
impl<I, S> Observer<I, S> for WriteCatcherObserver
where
    S: UsesInput + Unpin + HasMetadata,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), libafl::Error> {
        self.result = None;
        let Some(c) = self.c.as_ref() else {
            return Ok(());
        };
        assert!(c.start < c.end);
        let size = c.end - c.start;
        self.write_catcher.write_catcher_activate(c.start, size)
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &I,
        _e: &ExitKind,
    ) -> Result<(), libafl::Error> {
        self.result = Some(self.write_catcher.write_catcher_status()?);
        self.write_catcher.write_catcher_reset()
    }
}

impl Named for WriteCatcherObserver {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("WriteCatcherObserver")
    }
}

pub struct WriteCatcherFeedback {
    observer_handle: Handle<WriteCatcherObserver>,
    already_observed_messages: HashSet<u32>,
}

impl WriteCatcherFeedback {
    /// Creates a new [`TimeFeedback`], deciding if the given [`TimeObserver`] value of a run is interesting.
    #[must_use]
    pub fn new(observer: &WriteCatcherObserver) -> Self {
        Self {
            observer_handle: observer.handle(),
            already_observed_messages: HashSet::new(),
        }
    }
}

impl Named for WriteCatcherFeedback {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        self.observer_handle.name()
    }
}
impl<EM, I, OT, S> Feedback<EM, I, OT, S> for WriteCatcherFeedback
where
    OT: MatchName,
    S: HasMetadata,
{
    fn is_interesting(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _input: &I,
        observers: &OT,
        _exit_kind: &libafl::prelude::ExitKind,
    ) -> Result<bool, libafl::Error> {
        let mbox_meta: &MiscMetadata = state.metadata()?;
        let observer = observers.get(&self.observer_handle).unwrap();
        let Some(res) = &observer.result else {
            return Err(Error::illegal_state("No result from WriteCatcherObserver"));
        };
        if self
            .already_observed_messages
            .contains(&mbox_meta.mailbox_values.mbox)
        {
            return Ok(false);
        }
        if res.caught_read.is_some() || res.caught_write.is_some() {
            self.already_observed_messages
                .insert(mbox_meta.mailbox_values.mbox);
            return Ok(true);
        }

        Ok(false)
    }
    fn append_metadata(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        observers: &OT,
        testcase: &mut Testcase<I>,
    ) -> Result<(), Error> {
        let observer = observers.get(&self.observer_handle).unwrap();
        let Some(res) = &observer.result else {
            return Err(Error::illegal_state("No result from WriteCatcherObserver"));
        };
        testcase.add_metadata(res.clone());
        Ok(())
    }
}
impl<S> StateInitializer<S> for WriteCatcherFeedback {}
