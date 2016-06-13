import React from 'react';


class SliderItem extends React.Component {

  render () {


    var listyle = {
        background : '#888',
        borderRadius : '50%',
        display : 'inline-block',
        width : '20px',
        height : '20px',
        cursor : 'pointer',
        marginLeft: '20px',
        marginRight: '20px'
    }

    return (
        <li style={listyle}></li>
    );
  }
}

export default SliderItem;
