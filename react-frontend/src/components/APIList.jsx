import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Box, Container, Typography, Snackbar, Button } from '@mui/material';
import APICard from './APICard';
import './APIList.css';
import LoadingComponent from './Loading';
import { useNavigate } from 'react-router-dom';
import BASE_URL from './baseURL';

function APIList() {
  const [apis, setApis] = useState([]);
  const [loading, setLoading] = useState(true);
  const [prevLength, setPrevLength] = useState(0);
  const [snackPack, setSnackPack] = useState([]);
  const [open, setOpen] = useState(false);
  const [messageInfo, setMessageInfo] = useState(undefined);
  const navigate = useNavigate();

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (!token) {
      navigate('/login');
    }
    axios.get(`${BASE_URL}/api/routes`)
      .then(response => {
        setApis(response.data);
        const newLength = response.data.length;
        if (newLength > prevLength && prevLength !== 0) {
          enqueueSnackbar('API added', 'success');
        } else if (newLength < prevLength) {
          enqueueSnackbar('API removed', 'error');
        }
        setPrevLength(newLength);
        setLoading(false);
      })
      .catch(error => {
        console.error('There was an error fetching the API routes!', error);
        setLoading(false);
      });
  }, [apis]);

  const enqueueSnackbar = (message, variant) => {
    setSnackPack((prev) => [...prev, { message, key: new Date().getTime(), variant }]);
  };

  useEffect(() => {
    if (snackPack.length && !messageInfo) {
      setMessageInfo({ ...snackPack[0] });
      setSnackPack((prev) => prev.slice(1));
      setOpen(true);
    } else if (snackPack.length && messageInfo && open) {
      setOpen(false);
    }
  }, [snackPack, messageInfo, open]);

  const handleClose = (event, reason) => {
    if (reason === 'clickaway') {
      return;
    }
    setOpen(false);
  };

  const handleExited = () => {
    setMessageInfo(undefined);
  };

  if (loading) {
    return <LoadingComponent />;
  }

  return (
    <Box
      sx={{
        backgroundImage: 'url(/all_background.png)',
        backgroundSize: 'cover',
        backgroundPosition: 'center',
        backgroundAttachment: 'fixed',
        minHeight: '100vh',
        minWidth: '100vw',
        padding: '2rem 0',
        overflowX: 'hidden',
      }}
    >
      <Container maxWidth="lg" sx={{ position: 'relative', zIndex: 2 }}>
        <Typography
          variant="h4"
          align="center"
          gutterBottom
          sx={{ marginTop: '2rem', marginBottom: '1rem', color: '#fff' }}
        >
          List of APIs
        </Typography>
        <Typography
          variant="h6"
          align="center"
          gutterBottom
          sx={{ marginBottom: '2rem', color: '#fff' }}
        >
          Total APIs Found: {apis.length}
        </Typography>
        <Box className="horizontal-scroll">
          {apis.map((route, index) => (
            <div className="card-item" key={index}>
              <APICard path={route.path} method={route.methods} />
            </div>
          ))}
        </Box>
        <Snackbar
          key={messageInfo ? messageInfo.key : undefined}
          anchorOrigin={{
            vertical: 'top',
            horizontal: 'right',
          }}
          open={open}
          autoHideDuration={6000}
          onClose={handleClose}
          TransitionProps={{ onExited: handleExited }}
          message={messageInfo ? messageInfo.message : undefined}
          action={
            <Button color="primary" size="small" onClick={handleClose}>
              X
            </Button>
          }
        />
      </Container>
    </Box>
  );
}

export default APIList;
