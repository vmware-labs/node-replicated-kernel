// #[verifier(unforgeable)] // linear
// struct Alloc {
//     pub size: usize, 
// }
// 
// #[proof]
// pub split_alloc(a: Alloc, split_size: usize) -> (Alloc, Alloc) {
//     requires(split_size <= a.size);
// }
// 
// pub fn alloc(size: usize, #[proof] alloc: Alloc) -> *const u8 {
//     requires(size <= alloc.size);
// }
// 
// // NOTE: use linearity to track allocation requirements
// //
// pub function_that_alloc(a: u64, #[proof] alloc: Alloc) {
//     requires(alloc.size >= 32);
// }
// 
// pub kernel_main() {
//     #[proof] let all = reserve(32);
// 
//     give_up(all);
// }
