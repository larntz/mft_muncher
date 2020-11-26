//
// zipper implementation stolen/based on https://stackoverflow.com/a/36168919
//
//#[allow(dead_code)]

#[derive(Debug)]
pub struct Node<T> {
    pub data: T,
    pub children: Vec<Node<T>>,
}

impl<T> Node<T> {
    pub fn zipper(self) -> NodeZipper<T> {
        NodeZipper {
            node: self,
            parent: None,
            index_in_parent: 0,
        }
    }
}

#[derive(Debug)]
pub struct NodeZipper<T> {
    pub node: Node<T>,
    pub parent: Option<Box<NodeZipper<T>>>,
    pub index_in_parent: usize,
}

impl<T> NodeZipper<T> {
    fn delete(mut self) -> NodeZipper<T> {
        self.node = self.node.children.swap_remove(0);

        self
    }

    pub fn insert(mut self, node: Node<T>) -> NodeZipper<T> {
        self.node.children.push(node);

        self
    }

    fn modify(self, data: T) -> NodeZipper<T> {
        let n = Node {
            data,
            children: self.node.children,
        };

        NodeZipper {
            node: n,
            parent: self.parent,
            index_in_parent: self.index_in_parent,
        }
    }

    fn child(mut self, index: usize) -> NodeZipper<T> {
        // Remove the specified child from the node's children.
        // A NodeZipper shouldn't let its users inspect its parent,
        // since we mutate the parents
        // to move the focused nodes out of their list of children.
        // We use swap_remove() for efficiency.
        let child = self.node.children.swap_remove(index);

        // Return a new NodeZipper focused on the specified child.
        NodeZipper {
            node: child,
            parent: Some(Box::new(self)),
            index_in_parent: index,
        }
    }

    fn parent(self) -> NodeZipper<T> {
        // Destructure this NodeZipper
        let NodeZipper {
            node,
            parent,
            index_in_parent,
        } = self;

        // Destructure the parent NodeZipper
        let NodeZipper {
            node: mut parent_node,
            parent: parent_parent,
            index_in_parent: parent_index_in_parent,
        } = *parent.unwrap();

        // Insert the node of this NodeZipper back in its parent.
        // Since we used swap_remove() to remove the child,
        // we need to do the opposite of that.
        parent_node.children.push(node);
        let len = parent_node.children.len();
        parent_node.children.swap(index_in_parent, len - 1);

        // Return a new NodeZipper focused on the parent.
        NodeZipper {
            node: parent_node,
            parent: parent_parent,
            index_in_parent: parent_index_in_parent,
        }
    }

    fn finish(mut self) -> Node<T> {
        while let Some(_) = self.parent {
            self = self.parent();
        }

        self.node
    }
}
