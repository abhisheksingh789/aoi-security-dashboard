import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { AppBar, Toolbar, Typography, Button, Box, Container } from '@mui/material';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faShieldHalved } from '@fortawesome/free-solid-svg-icons';

function Home() {
  const navigate = useNavigate();
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  useEffect(() => {
    // Update the login state based on the presence of a token in local storage
    const token = localStorage.getItem('token');
    setIsLoggedIn(!!token);
  }, []);

  const handleNavigation = (path) => {
    if (!isLoggedIn) {
      navigate('/login');
    } else {
      navigate(path);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token'); // Remove the token from local storage
    setIsLoggedIn(false); // Update state to reflect the logout
    navigate('/'); // Optionally redirect the user to the homepage
  };

  return (
    <Box
      sx={{
        backgroundImage: 'url(/background.png)',
        backgroundSize: 'cover',
        backgroundPosition: 'center',
        height: '100vh',
        width: '100vw',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        flexDirection: 'column',
        color: '#ffffff',
        overflowX: 'hidden',
      }}
    >
      <AppBar position="static" sx={{ backgroundColor: 'transparent', boxShadow: 'none', width: '100%', maxWidth: '1200px' }}>
        <Toolbar>
          <Typography variant="h6" sx={{ flexGrow: 1 }}>
            API Security
          </Typography>
          <Button onClick={() => handleNavigation('/')} sx={{ color: '#ffffff', '&:hover': { color: '#c101fb' } }}>
            Home
          </Button>
          <Button onClick={() => handleNavigation('/dashboard')} sx={{ color: '#ffffff', '&:hover': { color: '#c101fb' } }}>
            Dashboard
          </Button>
          <Link to='/about'><Button sx={{ color: '#ffffff', '&:hover': { color: '#c101fb' } }}>
            About Us
          </Button></Link>
          {isLoggedIn ? (
            <Button onClick={handleLogout} sx={{ color: '#ffffff', '&:hover': { color: '#c101fb' } }}>
              Logout
            </Button>
          ) : (
            <Button onClick={() => handleNavigation('/login')} sx={{ color: '#ffffff', '&:hover': { color: '#c101fb' } }}>
              Login
            </Button>
          )}
        </Toolbar>
      </AppBar>

      <Container 
        maxWidth="md" 
        sx={{ 
          textAlign: 'center',
          flexGrow: 1,
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
        }}
      >
        <Typography variant="h2" sx={{ fontWeight: 'bold', marginBottom: '1rem' }}>
          API <span style={{ color: '#c101fb' }}>Security </span><FontAwesomeIcon icon={faShieldHalved} />
        </Typography>
        <Typography variant="h6" sx={{ marginBottom: '2rem' }}>
          Instant API security to inventory APIs, understand exposure, and achieve compliance.
        </Typography>
        <Box sx={{ display: 'flex', justifyContent: 'center', gap: 2 }}>
          <Button
            onClick={() => handleNavigation('/apis')}
            variant="contained"
            sx={{
              background: 'linear-gradient(90deg, #ff6a00, #ee0979)',
              padding: '10px 30px',
              fontSize: '1rem',
              fontWeight: 'bold',
              transition: 'all 1s ease',
              '&:hover': {
                color: 'black',
                background: 'linear-gradient(90deg, #ee0979, #ff6a00)',
              }
            }}
          >
            Show All APIs
          </Button>
          <Button
            onClick={() => handleNavigation('/vulnerabilities')}
            variant="outlined"
            sx={{
              border: '2px solid',
              borderImageSlice: 1,
              borderImageSource: 'linear-gradient(90deg, #ff6a00, #ee0979)',
              color: '#ffffff',
              backgroundColor: 'transparent',
              fontSize: '1rem',
              fontWeight: 'bold',
              transition: 'all 1s ease',
              '&:hover': {
                color: '#000',
                background: 'linear-gradient(90deg, #ff6a00, #ee0979)'
              },
            }}
          >
            Show Vulnerabilities
          </Button>
        </Box>
      </Container>
    </Box>
  );
}

export default Home;
