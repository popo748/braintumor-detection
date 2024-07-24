const sign_in_btn = document.querySelector("#sign-in-btn");
const sign_up_btn = document.querySelector("#sign-up-btn");
const container = document.querySelector(".container");

sign_up_btn.addEventListener("click", (e) => {
  console.log("Register button clicked");
  container.classList.add("sign-up-mode");
  e.preventDefault(); // Prevent default anchor tag behavior
});

sign_in_btn.addEventListener("click", (e) => {
  container.classList.remove("sign-up-mode");
  e.preventDefault(); // Prevent default anchor tag behavior
});