import React, { useState } from 'react';
import { Box, TextField, Button, Snackbar, Alert } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import BASE_URL from './baseURL';

function Login() {
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [openSnackbar, setOpenSnackbar] = useState(false);

  const handleLogin = async (event) => {
    event.preventDefault();
    try {
      const response = await axios.post(`${BASE_URL}/api/login`, { username, password });
      localStorage.setItem('token', response.data.access_token);
      navigate('/');
    } catch (error) {
      setOpenSnackbar(true);
    }
  };

  const handleCloseSnackbar = () => {
    setOpenSnackbar(false);
  };

  return (
    <Box
      sx={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: '100vh',
        minWidth: '100vw',
        backgroundImage: 'url(all_background.png)',
        backgroundSize: 'cover',
        padding: 3
      }}
    >
      <form onSubmit={handleLogin} style={{ width: '100%', maxWidth: 360 }}>
        <TextField
          fullWidth
          label="Username"
          margin="normal"
          variant="outlined"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          InputLabelProps={{
            style: { color: '#ffffff' } // Label color
          }}
          inputProps={{
            style: { color: '#ffffff' } // Text color
          }}
          sx={{
            '& .MuiOutlinedInput-root': {
              '& fieldset': {
                borderColor: '#ffffff', // Border color
              },
              '&:hover fieldset': {
                borderColor: '#ffffff', // Border color on hover
              },
              '&.Mui-focused fieldset': {
                borderColor: '#ffffff', // Border color on focus
              }
            }
          }}
        />
        <TextField
          fullWidth
          label="Password"
          type="password"
          margin="normal"
          variant="outlined"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          InputLabelProps={{
            style: { color: '#ffffff' } // Label color
          }}
          inputProps={{
            style: { color: '#ffffff' } // Text color
          }}
          sx={{
            '& .MuiOutlinedInput-root': {
              '& fieldset': {
                borderColor: '#ffffff', // Border color
              },
              '&:hover fieldset': {
                borderColor: '#ffffff', // Border color on hover
              },
              '&.Mui-focused fieldset': {
                borderColor: '#ffffff', // Border color on focus
              }
            }
          }}
        />
        <Button type="submit" fullWidth variant="contained" sx={{ mt: 3, mb: 2, color: '#ffffff', backgroundColor: '#c101fb', '&:hover': { backgroundColor: '#a000d0' } }}>
          Login
        </Button>
      </form>
      <Snackbar open={openSnackbar} autoHideDuration={6000} onClose={handleCloseSnackbar}
        anchorOrigin={{ vertical: 'top', horizontal: 'right' }}  // Position the Snackbar
      >
        <Alert onClose={handleCloseSnackbar} severity="error" sx={{ width: '100%' }}>
          Wrong credentials!
        </Alert>
      </Snackbar>
    </Box>
  );
}

export default Login;
