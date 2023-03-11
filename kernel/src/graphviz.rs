// Copyright © 2020-2021 VMware, Inc. All Rights Reserved.
// Copyright © 2014-2019 The Rust Project, All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Prints complex data-structures for visualization with [Graphviz](http://www.graphviz.org/)
//!
//! This code was ported from the rust compiler to work with the nrk kernel.
//!
//! # References
//! * [Original Source](https://github.com/rust-lang/rust/blob/4560cb830fce63fcffdc4558f4281aaac6a3a1ba/src/libgraphviz/lib.rs)
//! * [Graphviz](http://www.graphviz.org/)
//! * [DOT language](http://www.graphviz.org/doc/info/lang.html)

#![allow(unused)]

// Non-fallible data-structures and code in this file is ok, we don't use it for
// anything except debugging

use crate::alloc::string::ToString;
use alloc::borrow::Cow;
use alloc::string::String;
use alloc::{format, vec};
use core::fmt::Write;

use klogger::{sprint, sprintln};

use LabelText::*;

/// The text for a graphviz label on a node or edge.
pub(crate) enum LabelText<'a> {
    /// This kind of label preserves the text directly as is.
    ///
    /// Occurrences of backslashes (`\`) are escaped, and thus appear
    /// as backslashes in the rendered label.
    Label(Cow<'a, str>),

    /// This kind of label uses the graphviz label escString type:
    /// <http://www.graphviz.org/content/attrs#kescString>
    ///
    /// Occurrences of backslashes (`\`) are not escaped; instead they
    /// are interpreted as initiating an escString escape sequence.
    ///
    /// Escape sequences of particular interest: in addition to `\n`
    /// to break a line (centering the line preceding the `\n`), there
    /// are also the escape sequences `\l` which left-justifies the
    /// preceding line and `\r` which right-justifies it.
    Esc(Cow<'a, str>),

    /// This uses a graphviz [HTML string label][html]. The string is
    /// printed exactly as given, but between `<` and `>`. **No
    /// escaping is performed.**
    ///
    /// [html]: http://www.graphviz.org/content/node-shapes#html
    Html(Cow<'a, str>),
}

/// The style for a node or edge.
/// See <http://www.graphviz.org/doc/info/attrs.html#k:style> for descriptions.
/// Note that some of these are not valid for edges.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum Style {
    None,
    Solid,
    Dashed,
    Dotted,
    Bold,
    Rounded,
    Diagonals,
    Filled,
    Striped,
    Wedged,
}

impl Style {
    pub(crate) fn as_slice(self) -> &'static str {
        match self {
            Style::None => "",
            Style::Solid => "solid",
            Style::Dashed => "dashed",
            Style::Dotted => "dotted",
            Style::Bold => "bold",
            Style::Rounded => "rounded",
            Style::Diagonals => "diagonals",
            Style::Filled => "filled",
            Style::Striped => "striped",
            Style::Wedged => "wedged",
        }
    }
}

// There is a tension in the design of the labelling API.
//
// For example, I considered making a `Labeller<T>` trait that
// provides labels for `T`, and then making the graph type `G`
// implement `Labeller<Node>` and `Labeller<Edge>`. However, this is
// not possible without functional dependencies. (One could work
// around that, but I did not explore that avenue heavily.)
//
// Another approach that I actually used for a while was to make a
// `Label<Context>` trait that is implemented by the client-specific
// Node and Edge types (as well as an implementation on Graph itself
// for the overall name for the graph). The main disadvantage of this
// second approach (compared to having the `G` type parameter
// implement a Labelling service) that I have encountered is that it
// makes it impossible to use types outside of the current crate
// directly as Nodes/Edges; you need to wrap them in newtype'd
// structs. See e.g., the `No` and `Ed` structs in the examples. (In
// practice clients using a graph in some other crate would need to
// provide some sort of adapter shim over the graph anyway to
// interface with this library).
//
// Another approach would be to make a single `Labeller<N,E>` trait
// that provides three methods (graph_label, node_label, edge_label),
// and then make `G` implement `Labeller<N,E>`. At first this did not
// appeal to me, since I had thought I would need separate methods on
// each data variant for dot-internal identifiers versus user-visible
// labels. However, the identifier/label distinction only arises for
// nodes; graphs themselves only have identifiers, and edges only have
// labels.
//
// So in the end I decided to use the third approach described above.

/// `Id` is a Graphviz `ID`.
pub(crate) struct Id<'a> {
    name: Cow<'a, str>,
}

impl<'a> Id<'a> {
    /// Creates an `Id` named `name`.
    ///
    /// The caller must ensure that the input conforms to an
    /// identifier format: it must be a non-empty string made up of
    /// alphanumeric or underscore characters, not beginning with a
    /// digit (i.e., the regular expression `[a-zA-Z_][a-zA-Z_0-9]*`).
    ///
    /// (Note: this format is a strict subset of the `ID` format
    /// defined by the DOT language. This function may change in the
    /// future to accept a broader subset, or the entirety, of DOT's
    /// `ID` format.)
    ///
    /// Passing an invalid string (containing spaces, brackets,
    /// quotes, ...) will return an empty `Err` value.
    pub(crate) fn new<Name: Into<Cow<'a, str>>>(name: Name) -> Result<Id<'a>, ()> {
        let name = name.into();
        /*match name.chars().next() {
            Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
            _ => return Err(()),
        }
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(());
        }*/

        Ok(Id { name })
    }

    pub(crate) fn as_slice(&'a self) -> &'a str {
        &self.name
    }

    pub(crate) fn name(self) -> Cow<'a, str> {
        self.name
    }
}

/// Each instance of a type that implements `Label<C>` maps to a
/// unique identifier with respect to `C`, which is used to identify
/// it in the generated .dot file. They can also provide more
/// elaborate (and non-unique) label text that is used in the graphviz
/// rendered output.

/// The graph instance is responsible for providing the DOT compatible
/// identifiers for the nodes and (optionally) rendered labels for the nodes and
/// edges, as well as an identifier for the graph itself.
pub(crate) trait Labeller<'a> {
    type Node;
    type Edge;

    /// Must return a DOT compatible identifier naming the graph.
    fn graph_id(&'a self) -> Id<'a>;

    /// Maps `n` to a unique identifier with respect to `self`. The
    /// implementor is responsible for ensuring that the returned name
    /// is a valid DOT identifier.
    fn node_id(&'a self, n: &Self::Node) -> Id<'a>;

    /// Maps `n` to one of the [graphviz `shape` names][1]. If `None`
    /// is returned, no `shape` attribute is specified.
    ///
    /// [1]: http://www.graphviz.org/content/node-shapes
    fn node_shape(&'a self, _node: &Self::Node) -> Option<LabelText<'a>> {
        None
    }

    /// Maps `n` to a label that will be used in the rendered output.
    /// The label need not be unique, and may be the empty string; the
    /// default is just the output from `node_id`.
    fn node_label(&'a self, n: &Self::Node) -> LabelText<'a> {
        Label(self.node_id(n).name)
    }

    /// Maps `e` to a label that will be used in the rendered output.
    /// The label need not be unique, and may be the empty string; the
    /// default is in fact the empty string.
    fn edge_label(&'a self, _e: &Self::Edge) -> LabelText<'a> {
        Label("".into())
    }

    /// Maps `n` to a style that will be used in the rendered output.
    fn node_style(&'a self, _n: &Self::Node) -> Style {
        Style::None
    }

    /// Maps `e` to a style that will be used in the rendered output.
    fn edge_style(&'a self, _e: &Self::Edge) -> Style {
        Style::None
    }
}

/// Escape tags in such a way that it is suitable for inclusion in a
/// Graphviz HTML label.
pub(crate) fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

impl<'a> LabelText<'a> {
    pub(crate) fn label<S: Into<Cow<'a, str>>>(s: S) -> LabelText<'a> {
        Label(s.into())
    }

    pub(crate) fn escaped<S: Into<Cow<'a, str>>>(s: S) -> LabelText<'a> {
        Esc(s.into())
    }

    pub(crate) fn html<S: Into<Cow<'a, str>>>(s: S) -> LabelText<'a> {
        Html(s.into())
    }

    fn escape_char<F>(c: char, mut f: F)
    where
        F: FnMut(char),
    {
        match c {
            // not escaping \\, since Graphviz escString needs to
            // interpret backslashes; see Esc above.
            '\\' => f(c),
            _ => {
                for c in c.escape_default() {
                    f(c)
                }
            }
        }
    }
    fn escape_str(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for c in s.chars() {
            LabelText::escape_char(c, |c| out.push(c));
        }
        out
    }

    /// Renders text as string suitable for a label in a .dot file.
    /// This includes quotes or suitable delimiters.
    pub(crate) fn to_dot_string(&self) -> String {
        match *self {
            Label(ref s) => format!("\"{}\"", s.escape_default()),
            Esc(ref s) => format!("\"{}\"", LabelText::escape_str(s)),
            Html(ref s) => format!("<{}>", s),
        }
    }

    /// Decomposes content into string suitable for making Esc that
    /// yields same content as self. The result obeys the law
    /// render(`lt`) == render(`Esc(lt.pre_escaped_content())`) for
    /// all `lt: LabelText`.
    fn pre_escaped_content(self) -> Cow<'a, str> {
        match self {
            Esc(s) => s,
            Label(s) => {
                if s.contains('\\') {
                    (*s).escape_default().to_string().into()
                } else {
                    s
                }
            }
            Html(s) => s,
        }
    }

    /// Puts `prefix` on a line above this label, with a blank line separator.
    pub(crate) fn prefix_line(self, prefix: LabelText<'_>) -> LabelText<'static> {
        prefix.suffix_line(self)
    }

    /// Puts `suffix` on a line below this label, with a blank line separator.
    pub(crate) fn suffix_line(self, suffix: LabelText<'_>) -> LabelText<'static> {
        let mut prefix = self.pre_escaped_content().into_owned();
        let suffix = suffix.pre_escaped_content();
        prefix.push_str(r"\n\n");
        prefix.push_str(&suffix);
        Esc(prefix.into())
    }
}

pub(crate) type Nodes<'a, N> = Cow<'a, [N]>;
pub(crate) type Edges<'a, E> = Cow<'a, [E]>;

// (The type parameters in GraphWalk should be associated items,
// when/if Rust supports such.)

/// GraphWalk is an abstraction over a directed graph = (nodes,edges)
/// made up of node handles `N` and edge handles `E`, where each `E`
/// can be mapped to its source and target nodes.
///
/// The lifetime parameter `'a` is exposed in this trait (rather than
/// introduced as a generic parameter on each method declaration) so
/// that a client impl can choose `N` and `E` that have substructure
/// that is bound by the self lifetime `'a`.
///
/// The `nodes` and `edges` method each return instantiations of
/// `Cow<[T]>` to leave implementors the freedom to create
/// entirely new vectors or to pass back slices into internally owned
/// vectors.
pub(crate) trait GraphWalk<'a> {
    type Node: Clone;
    type Edge: Clone;

    /// Returns all the nodes in this graph.
    fn nodes(&'a self) -> Nodes<'a, Self::Node>;
    /// Returns all of the edges in this graph.
    fn edges(&'a self) -> Edges<'a, Self::Edge>;
    /// The source node for `edge`.
    fn source(&'a self, edge: &Self::Edge) -> Self::Node;
    /// The target node for `edge`.
    fn target(&'a self, edge: &Self::Edge) -> Self::Node;
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum RenderOption {
    NoEdgeLabels,
    NoNodeLabels,
    NoEdgeStyles,
    NoNodeStyles,
    RankDirectionLR,
}

/// Renders directed graph `g` in DOT syntax.
/// (Simple wrapper around `render_opts` that passes a default set of options.)
pub(crate) fn render<'a, N, E, G>(g: &'a G)
where
    N: Clone + 'a,
    E: Clone + 'a,
    G: Labeller<'a, Node = N, Edge = E> + GraphWalk<'a, Node = N, Edge = E>,
{
    render_opts(g, &[])
}

/// Renders directed graph `g` in DOT syntax.
/// (Main entry point for the library.)
pub(crate) fn render_opts<'a, N, E, G>(g: &'a G, options: &[RenderOption])
where
    N: Clone + 'a,
    E: Clone + 'a,
    G: Labeller<'a, Node = N, Edge = E> + GraphWalk<'a, Node = N, Edge = E>,
{
    // test vspace_debug depends on this line:
    sprintln!("===== graphviz =====");

    sprintln!("digraph {} {{", g.graph_id().as_slice());

    if options.contains(&RenderOption::RankDirectionLR) {
        sprintln!("graph [ rankdir = \"LR\" ];");
    }

    for n in g.nodes().iter() {
        sprint!("    ");
        let id = g.node_id(n);

        let escaped = &g.node_label(n).to_dot_string();

        sprint!("{}", id.as_slice());

        if !options.contains(&RenderOption::NoNodeLabels) {
            sprint!("[label={}]", escaped);
        }

        let style = g.node_style(n);
        if !options.contains(&RenderOption::NoNodeStyles) && style != Style::None {
            sprint!("[style=\"{}\"]", style.as_slice());
        }

        if let Some(s) = g.node_shape(n) {
            sprint!("[shape={}]", &s.to_dot_string());
        }

        sprintln!(";");
    }

    for e in g.edges().iter() {
        let escaped_label = &g.edge_label(e).to_dot_string();
        sprint!("    ");
        let source = g.source(e);
        let target = g.target(e);
        let source_id = g.node_id(&source);
        let target_id = g.node_id(&target);

        sprint!("{} -> {}", source_id.as_slice(), target_id.as_slice());

        if !options.contains(&RenderOption::NoEdgeLabels) {
            sprint!("[label={}]", escaped_label);
        }

        let style = g.edge_style(e);
        if !options.contains(&RenderOption::NoEdgeStyles) && style != Style::None {
            sprint!("[style=\"{}\"]", style.as_slice());
        }

        sprintln!(";");
    }

    sprintln!("}}");

    // test vspace_debug depends on this line:
    sprintln!("===== end graphviz =====");
}
