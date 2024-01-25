const handleNav= document.getElementById('handle-nav');
const closeNav = document.getElementById('close-nav');
const nav = document.querySelector('.mobile-nav');

handleNav.addEventListener('click', () => {
    console.log('clicked');
    nav.classList.toggle('show');
    
});
closeNav.addEventListener('click', () => {
    nav.classList.toggle('show');
    
}
);